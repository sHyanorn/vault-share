#!/usr/bin/env python3
"""Black-box security checks against a running vault-share instance.

Run it only against instances you operate. It creates and deletes files,
sends bad signatures until a file locks, and uses up its own rate limits.

    python3 scripts/blackbox.py http://127.0.0.1:8080
    python3 scripts/blackbox.py https://localhost --cafile root.crt --http-url http://localhost

Standard library only. Exits 1 when a check fails.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.parse
import warnings

API = "/api/v1/files"
ACCOUNT = "/api/v1/account"
SESSION = "/api/v1/session"
NOT_FOUND = b'{"error":{"code":"not_found","message":"not found"}}\n'
# Strings that must never reach a client: stack traces, SQL errors, file contents.
LEAKS = re.compile(
    rb"goroutine |\.go:\d|panic|sqlite|SQL logic|syntax error|root:x:0:0|\[core\]|SQLite format 3|VAULT_",
    re.IGNORECASE,
)
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def random_id():
    return b64(secrets.token_bytes(16))


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name):
        return self.headers.get(name)

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    @property
    def code(self):
        data = self.json()
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            return data["error"].get("code")
        return None


class Client:
    def __init__(self, base_url, cafile=None):
        url = urllib.parse.urlsplit(base_url)
        self.scheme, self.host = url.scheme, url.hostname
        self.port = url.port or (443 if url.scheme == "https" else 80)
        self.origin = f"{url.scheme}://{url.netloc}"
        self.context = ssl.create_default_context(cafile=cafile) if url.scheme == "https" else None

    def connect(self, timeout=30):
        if self.context:
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.context)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def raw_socket(self):
        """A socket to the instance, TLS-wrapped for https, for bytes http.client would not send."""
        sock = socket.create_connection((self.host, self.port), timeout=5)
        return self.context.wrap_socket(sock, server_hostname=self.host) if self.context else sock

    def request(self, method, path, body=None, headers=None, wait=True):
        """Sends one request on a fresh connection. Unless wait is false, a 429
        is answered by sleeping for Retry-After and trying again."""
        for _ in range(6):
            conn = self.connect()
            try:
                conn.request(method, path, body=body, headers=headers or {})
                resp = conn.getresponse()
                result = Response(resp.status, resp.headers, resp.read())
            finally:
                conn.close()
            if result.status != 429 or not wait:
                return result
            time.sleep(min(int(result.header("Retry-After") or 1), 60))
        return result

    def json(self, method, path, value, headers=None, wait=True):
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
        return self.request(method, path, body, headers, wait)


class Share:
    """A test file: what the uploader holds after creating it."""

    def __init__(self, file_id, owner, auth_key, size):
        self.id, self.owner, self.auth_key = file_id, owner, auth_key
        self.content = secrets.token_bytes(size)

    @property
    def bearer(self):
        return {"Authorization": "Bearer " + self.owner}


def create_body(size=64, max_downloads=5, auth_key=None):
    return {
        "size": size,
        "meta": b64(secrets.token_bytes(40)),
        "auth_key": b64(auth_key or secrets.token_bytes(32)),
        "expires_in": 3600,
        "max_downloads": max_downloads,
    }


class Account:
    """A test account. The secrets stand in for what a browser derives from a
    password (D026); to the server they are only bytes of the right length."""

    def __init__(self, username):
        self.username = username
        self.salt, self.auth, self.sealed = secrets.token_bytes(16), secrets.token_bytes(32), secrets.token_bytes(60)
        self.cookies = {}
        self.recovery = []

    def headers(self, extra=None):
        cookie = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return {**({"Cookie": cookie} if cookie else {}), **(extra or {})}

    def absorb(self, response):
        """Keeps cookies as a browser would, dropping those set to expire."""
        for line in response.headers.get_all("Set-Cookie") or []:
            name, _, rest = line.partition("=")
            value = rest.split(";", 1)[0]
            if re.search(r"(?i);\s*Max-Age=0", line):
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        return response


def totp(secret, steps=0):
    """RFC 6238 with SHA-1, 30-second steps and six digits."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = (int(time.time()) // 30 + steps).to_bytes(8, "big")
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    offset = mac[-1] & 15
    return f"{(int.from_bytes(mac[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


class Tester:
    def __init__(self, client, http=None):
        self.c = client
        self.http = http
        self.shares = []
        self.accounts = []
        self.counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        self.check = ""

    def report(self, status, what, detail=""):
        self.counts[status] += 1
        line = f"{status}  {self.check:<12} {what}"
        print(line + (f"  ({detail})" if detail else ""), flush=True)

    def ok(self, cond, what, detail=""):
        self.report("PASS" if cond else "FAIL", what, "" if cond else detail)
        return cond

    def skip(self, what, detail=""):
        self.report("SKIP", what, detail)

    def create(self, size=64, max_downloads=5, headers=None, wait=True):
        auth_key = secrets.token_bytes(32)
        r = self.c.json("POST", API, create_body(size, max_downloads, auth_key), headers, wait)
        if r.status != 201:
            return r, None
        data = r.json()
        share = Share(data["id"], data["owner_token"], auth_key, size)
        self.shares.append(share)
        return r, share

    def upload(self, share, body=None, headers=None):
        body = share.content if body is None else body
        return self.c.request("PUT", f"{API}/{share.id}/content", body, {**share.bearer, **(headers or {})})

    def ready(self, size=64, max_downloads=5):
        """Creates and uploads a share; raises when the instance refuses."""
        r, share = self.create(size, max_downloads)
        if share is None:
            raise RuntimeError(f"create answered {r.status} {r.body[:80]!r}")
        r = self.upload(share)
        if r.status != 204:
            raise RuntimeError(f"upload answered {r.status} {r.body[:80]!r}")
        return share

    def grant(self, share, key=None):
        """Signs a fresh challenge with key (the share's auth key by default)."""
        r = self.c.request("GET", f"{API}/{share.id}/meta")
        if r.status != 200:
            return r
        challenge = unb64(r.json()["challenge"])
        signature = hmac.new(key or share.auth_key, challenge, hashlib.sha256).digest()
        body = {"challenge": b64(challenge), "signature": b64(signature)}
        return self.c.json("POST", f"{API}/{share.id}/download", body)

    def content(self, share_id, token):
        return self.c.request("GET", f"{API}/{share_id}/content?token={token}")

    def account(self):
        """The one test account, opened on first use: a client may open only
        five an hour, and the browser checks and end-to-end tests need theirs."""
        if not self.accounts:
            acct = Account("bb-" + secrets.token_hex(5))
            r = acct.absorb(self.c.json("POST", ACCOUNT, {
                "username": acct.username, "salt": b64(acct.salt), "auth": b64(acct.auth), "sealed_key": b64(acct.sealed),
            }))
            if r.status != 201:
                raise RuntimeError(f"sign-up answered {r.status} {r.body[:80]!r}")
            acct.signup = r
            self.accounts.append(acct)
        return self.accounts[0]

    def sign_in(self, acct, auth=None, wait=True):
        """The first step of a sign-in; cookies it sets go to acct."""
        body = {"username": acct.username, "auth": b64(auth or acct.auth)}
        return acct.absorb(self.c.json("POST", SESSION, body, acct.headers(), wait))

    def cleanup(self):
        """Deletes every test file and account; returns how many deletions failed."""
        failed = 0
        for acct in self.accounts:
            code = acct.recovery.pop() if acct.recovery else None
            body = {"auth": b64(acct.auth), **({"code": code} if code else {})}
            try:
                status = self.c.json("DELETE", ACCOUNT, body, acct.headers()).status
            except OSError:
                status = None
            failed += status != 204
        for share in self.shares:
            try:
                status = self.c.request("DELETE", f"{API}/{share.id}", headers=share.bearer).status
            except OSError:
                status = None
            failed += status not in (204, 404)  # 404: burned or deleted by a check
        return failed


def check_tls(t):
    c = t.c
    if c.scheme != "https":
        t.skip("TLS", "target is plain HTTP")
        return
    with socket.create_connection((c.host, c.port), timeout=10) as sock:
        with c.context.wrap_socket(sock, server_hostname=c.host) as tls:
            version, cipher = tls.version(), tls.cipher()[0]
    t.ok(version in ("TLSv1.2", "TLSv1.3"), f"negotiates {version} with {cipher}, certificate verified")

    def probe(setup):
        """"refused" when the server refuses the offer, None when the local
        TLS library cannot make it, otherwise what happened."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # The probe sends no data; only the server's answer to the offer counts,
        # so a certificate or renegotiation complaint must not end it early.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # nosemgrep
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
        try:
            setup(ctx)
        except (ValueError, ssl.SSLError):
            return None
        try:
            with socket.create_connection((c.host, c.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=c.host) as tls:
                    return f"accepted {tls.version()} {tls.cipher()[0]}"
        except (ssl.SSLEOFError, ConnectionResetError):
            return "refused"
        except ssl.SSLError as e:
            reason = e.reason or ""
            if reason in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"):
                return None
            if reason.startswith(("TLSV1_ALERT_", "SSLV3_ALERT_")) or reason in ("UNSUPPORTED_PROTOCOL", "WRONG_VERSION_NUMBER"):
                return "refused"
            return f"failed in the client: {reason or e}"

    def only(version):
        def setup(ctx):
            with warnings.catch_warnings():  # the old versions are the point of the probe
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = version
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        return setup

    def cbc(ctx):
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AES+SHA1:ECDHE+AES+SHA256:RSA+AES:DES-CBC3-SHA:@SECLEVEL=0")

    for name, setup in (
        ("TLS 1.0", only(ssl.TLSVersion.TLSv1)),
        ("TLS 1.1", only(ssl.TLSVersion.TLSv1_1)),
        ("TLS 1.2 with CBC or RSA key exchange suites", cbc),
    ):
        outcome = probe(setup)
        if outcome is None:
            t.skip(f"refuses {name}", "the local TLS library cannot offer it")
        else:
            t.ok(outcome == "refused", f"refuses {name}", outcome)


def check_redirect(t):
    if not t.http:
        t.skip("HTTP redirects to HTTPS", "no --http-url given")
        return
    r = t.http.request("GET", "/f/abc?x=1")
    location = r.header("Location") or ""
    t.ok(r.status in (301, 308) and location == t.c.origin + "/f/abc?x=1",
         "plain HTTP answers a permanent redirect to the same HTTPS URL", f"{r.status} {location}")


def first_asset(t):
    r = t.c.request("GET", "/")
    match = re.search(rb'src="(/assets/[^"]+\.js)"', r.body)
    return r, match.group(1).decode() if match else None


def check_headers(t):
    _, asset = first_asset(t)
    targets = [("GET", "/"), ("GET", "/f/" + random_id()), ("GET", "/healthz"),
               ("GET", f"{API}/{random_id()}/meta"), ("PATCH", API), ("POST", "/api/v1/nope")]
    if asset:
        targets.insert(1, ("GET", asset))
    for method, path in targets:
        r = t.c.request(method, path)
        problems = [f"{k}: {r.header(k)}" for k, v in HEADERS.items() if r.header(k) != v]
        problems += csp_problems(r.header("Content-Security-Policy"))
        hsts = r.header("Strict-Transport-Security") or ""
        age = re.search(r"max-age=(\d+)", hsts)
        if not age or int(age.group(1)) < 31536000 or "includesubdomains" not in hsts.lower():
            problems.append(f"HSTS: {hsts or 'missing'}")
        permissions = r.header("Permissions-Policy") or ""
        problems += [f"Permissions-Policy lacks {f}" for f in ("camera=()", "microphone=()", "geolocation=()")
                     if f not in permissions]
        if r.header("X-Powered-By") or re.search(r"\d", r.header("Server") or ""):
            problems.append(f"banner: {r.header('Server')} {r.header('X-Powered-By')}")
        t.ok(not problems, f"{method} {path} [{r.status}] carries every security header", "; ".join(problems))


def csp_problems(policy):
    if not policy:
        return ["CSP missing"]
    directives = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    problems = []
    for name in ("script-src", "style-src"):
        sources = directives.get(name, directives.get("default-src", []))
        problems += [f"{name} allows {s}" for s in sources
                     if s in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:", "http:", "https:")]
    for name in ("object-src", "base-uri", "frame-ancestors", "form-action"):
        if directives.get(name) != ["'none'"]:
            problems.append(f"{name} is {directives.get(name)}")
    if directives.get("default-src") != ["'self'"]:
        problems.append(f"default-src is {directives.get('default-src')}")
    return problems


def check_page(t):
    r, asset = first_asset(t)
    inline = re.findall(rb"<script(?![^>]*\bsrc=)[^>]*>", r.body)
    handlers = re.findall(rb"<[^>]+\s(on[a-z]+|style)\s*=", r.body)
    t.ok(not inline and not handlers, "index.html has no inline script, event handler or style attribute",
         f"{inline} {handlers}")
    if not asset:
        t.ok(False, "index.html references a script bundle")
        return
    js = t.c.request("GET", asset)
    t.ok(b"sourceMappingURL" not in js.body, "the bundle references no source map")
    m = t.c.request("GET", asset + ".map")
    t.ok(b'"mappings"' not in m.body, "no source map is served next to the bundle")


def check_cache(t):
    r, share = t.create(max_downloads=2)
    t.ok(share and "no-store" in (r.header("Cache-Control") or ""), "create response is no-store")
    if not share:
        return
    t.upload(share)
    meta = t.c.request("GET", f"{API}/{share.id}/meta")
    t.ok("no-store" in (meta.header("Cache-Control") or ""), "metadata and challenge are no-store")
    grant = t.grant(share)
    t.ok("no-store" in (grant.header("Cache-Control") or ""), "download token response is no-store")
    body = t.content(share.id, grant.json()["token"])
    t.ok(body.status == 200 and body.body == share.content, "the ciphertext comes back unchanged")
    t.ok("no-store" in (body.header("Cache-Control") or ""), "ciphertext response is no-store")
    t.ok(body.header("Content-Type") == "application/octet-stream" and body.header("Content-Disposition") == "attachment",
         "ciphertext is an attachment of type application/octet-stream",
         f"{body.header('Content-Type')} / {body.header('Content-Disposition')}")


def check_cors(t):
    evil = {"Origin": "https://attacker.example"}
    share = t.ready()
    for method, path in (("GET", f"{API}/{share.id}/meta"), ("GET", f"{API}/{random_id()}/meta"), ("GET", "/healthz")):
        r = t.c.request(method, path, headers=evil)
        t.ok(r.header("Access-Control-Allow-Origin") is None, f"{method} {path} [{r.status}] grants no cross-origin read")
    pre = t.c.request("OPTIONS", API, headers={**evil, "Access-Control-Request-Method": "POST",
                                                "Access-Control-Request-Headers": "content-type"})
    t.ok(pre.status >= 400 and not pre.header("Access-Control-Allow-Origin") and not pre.header("Access-Control-Allow-Methods"),
         f"CORS preflight is refused [{pre.status}]")


def check_cross_site(t):
    """A page on another site can send a simple POST without a preflight and
    cannot read the answer, but the request still takes effect."""
    simple = {"Content-Type": "text/plain"}
    cases = (
        ("cross-site POST with fetch metadata", {**simple, "Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"}, False),
        ("cross-origin POST from an older browser", {**simple, "Origin": "https://attacker.example"}, False),
        ("same-origin POST", {"Origin": t.c.origin, "Sec-Fetch-Site": "same-origin"}, True),
        ("POST from a non-browser client", {}, True),
    )
    for name, headers, allowed in cases:
        r, share = t.create(headers=headers)
        if allowed:
            t.ok(share is not None, f"{name} creates a file", f"{r.status} {r.code}")
        else:
            t.ok(r.status == 403 and r.code == "cross_origin", f"{name} is refused", f"{r.status} {r.code}")
    r = t.c.request("GET", f"{API}/{random_id()}/meta", headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"})
    t.ok(r.status == 403 and r.code == "cross_origin", "cross-site read is refused", f"{r.status} {r.code}")


def check_methods(t):
    share = t.ready()
    canary = "trace-canary-" + secrets.token_hex(4)
    for path in ("/", "/healthz", API, f"{API}/{share.id}/meta"):
        for method in ("TRACE", "OPTIONS", "PATCH", "PROPFIND", "FOO"):
            r = t.c.request(method, path, headers={"X-Canary": canary})
            t.ok(r.status == 405 and canary.encode() not in r.body, f"{method} {path} is refused [{r.status}]")
    override = t.c.request("POST", f"{API}/{share.id}", b"", {**share.bearer, "X-HTTP-Method-Override": "DELETE",
                                                              "X-HTTP-Method": "DELETE", "X-Method-Override": "DELETE"})
    query = t.c.request("GET", f"{API}/{share.id}?_method=DELETE", headers=share.bearer)
    alive = t.c.request("GET", f"{API}/{share.id}/meta").status == 200
    t.ok(override.status == 405 and query.status in (404, 405) and alive,
         "method override headers and parameters are ignored", f"{override.status} {query.status} alive={alive}")


def check_errors(t):
    cases = [
        ("malformed JSON", "POST", API, b"{", {"Content-Type": "application/json"}),
        ("unknown API route", "GET", "/api/v1/admin", None, {}),
        ("oversized header", "GET", "/healthz", None, {"X-Big": "a" * (80 << 10)}),
        ("bad download body", "POST", f"{API}/{random_id()}/download", b'{"challenge":1}', {"Content-Type": "application/json"}),
    ]
    for name, method, path, body, headers in cases:
        r = t.c.request(method, path, body, headers)
        t.ok(400 <= r.status < 500 and not LEAKS.search(r.body),
             f"{name} gets a client error without internals [{r.status}]", r.body[:120])


def check_traversal(t):
    index = t.c.request("GET", "/").body
    paths = [
        "/../../../../etc/passwd", "/..%2f..%2f..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd", "/assets/../../../../etc/passwd", "/assets/..%2f..%2f..%2fetc%2fpasswd",
        "/..\\..\\..\\etc\\passwd", "/assets/", "/assets", "/.git/config", "/.env", "/vault.db", "/data/vault.db",
        "/audit.key", "/data/audit.key", "/blobs/", "/proc/self/environ", "/index.html%00.js",
    ]
    for path in paths:
        r = t.c.request("GET", path)
        spa = r.status == 200 and r.body == index
        t.ok((spa or r.status in (400, 404)) and not LEAKS.search(r.body) and b"<pre>" not in r.body,
             f"GET {path} serves no file outside the web root [{r.status}{', app shell' if spa else ''}]", r.body[:80])
    for path in (f"{API}/..%2f..%2fvault.db/meta", f"{API}/%2e%2e/meta", f"{API}/..%2F..%2Fdata%2Faudit.key/content?token=x"):
        r = t.c.request("GET", path)
        t.ok(r.status in (400, 404) and not LEAKS.search(r.body), f"GET {path} is refused [{r.status}]")


def check_input(t):
    valid = create_body()

    def with_(**fields):
        return {**valid, **fields}

    cases = [
        ("JSON array", b"[]"),
        ("unknown field", with_(admin=True)),
        ("body over 16 KiB", json.dumps(valid).encode()[:-1] + b" " * (20 << 10) + b"}"),
        ("meta not base64url", with_(meta="!!!!" * 10)),
        ("meta with padding", with_(meta=base64.urlsafe_b64encode(secrets.token_bytes(40)).decode())),
        ("meta under 28 bytes", with_(meta=b64(secrets.token_bytes(27)))),
        ("meta over 4096 bytes", with_(meta=b64(secrets.token_bytes(4097)))),
        ("SQL in meta", with_(meta="' OR 1=1; DROP TABLE files;--")),
        ("size below the ciphertext minimum", with_(size=37)),
        ("negative size", with_(size=-1)),
        ("size over the limit", with_(size=2**62)),
        ("size as a string", with_(size="64")),
        ("fractional size", with_(size=64.5)),
        ("null fields", with_(size=None, max_downloads=None)),
        ("expiry not offered", with_(expires_in=7200)),
        ("zero downloads", with_(max_downloads=0)),
        ("101 downloads", with_(max_downloads=101)),
        ("31-byte auth key", with_(auth_key=b64(secrets.token_bytes(31)))),
        ("33-byte auth key", with_(auth_key=b64(secrets.token_bytes(33)))),
    ]
    for name, body in cases:
        r = t.c.json("POST", API, body)
        t.ok(r.status == 400 and r.code in ("invalid_request", "too_large") and not LEAKS.search(r.body),
             f"create rejects {name} [{r.status} {r.code}]", r.body[:120])
        if r.status == 201:
            data = r.json()
            t.c.request("DELETE", f"{API}/{data['id']}", headers={"Authorization": "Bearer " + data["owner_token"]})
    for path in (f"{API}/'%20OR%20'1'='1/meta", f"{API}/{random_id()}'--/meta",
                 f"{API}/{random_id()}/content?token='%20OR%20'1'='1", f"{API}/%00/meta"):
        r = t.c.request("GET", path)
        t.ok(r.status in (400, 404) and (r.status == 400 or r.body == NOT_FOUND) and not LEAKS.search(r.body),
             f"GET {path} is refused without detail [{r.status}]", r.body[:80])


def check_not_found(t):
    live = t.ready(max_downloads=3)
    gone = t.ready()
    t.c.request("DELETE", f"{API}/{gone.id}", headers=gone.bearer)
    wrong = {"Authorization": "Bearer " + b64(secrets.token_bytes(32))}
    signed = {"challenge": b64(secrets.token_bytes(32)), "signature": b64(secrets.token_bytes(32))}
    token = b64(secrets.token_bytes(32))
    cases = []
    for label, file_id in (("live", live.id), ("missing", random_id()), ("deleted", gone.id), ("malformed", "not-an-id")):
        if label != "live":  # a live file's metadata answers 200
            cases.append((f"metadata of a {label} id", "GET", f"{API}/{file_id}/meta", None, {}))
        cases += [
            (f"content of a {label} id with a wrong token", "GET", f"{API}/{file_id}/content?token={token}", None, {}),
            (f"upload to a {label} id with a wrong owner token", "PUT", f"{API}/{file_id}/content", b"x" * 64, wrong),
            (f"delete of a {label} id with a wrong owner token", "DELETE", f"{API}/{file_id}", None, wrong),
            (f"download of a {label} id with a bad signature", "POST", f"{API}/{file_id}/download",
             json.dumps(signed).encode(), {"Content-Type": "application/json"}),
        ]
    for name, method, path, body, headers in cases:
        r = t.c.request(method, path, body, headers)
        t.ok(r.status == 404 and r.body == NOT_FOUND, f"{name} is the same 404", f"{r.status} {r.body[:80]!r}")
    bad = b'{"challenge":"x"}'
    answers = {t.c.request("POST", f"{API}/{i}/download", bad, {"Content-Type": "application/json"}).status
               for i in (live.id, random_id())}
    t.ok(answers == {400}, "a malformed download body gets 400 for live and missing ids alike", str(answers))


def check_access(t):
    a, b = t.create(max_downloads=2)[1], t.create()[1]
    t.ok(t.c.request("PUT", f"{API}/{a.id}/content", a.content).status == 404, "upload without the owner token is refused")
    t.ok(t.upload(a, headers=b.bearer).status == 404, "another file's owner token cannot upload")
    t.ok(t.upload(a).status == 204 and t.upload(b).status == 204, "the owner token uploads its own file")
    t.ok(t.grant(a, key=b.auth_key).status == 404, "a signature with another file's key is refused")
    token = t.grant(a).json()["token"]
    t.ok(t.content(b.id, token).status == 404, "a download token is bound to its file")
    first, second = t.content(a.id, token), t.content(a.id, token)
    t.ok(first.status == 200 and first.body == a.content and second.status == 404, "a download token works once")
    t.ok(t.content(a.id, a.owner).status == 404, "the owner token is no download token")
    t.ok(t.c.request("DELETE", f"{API}/{a.id}", headers=b.bearer).status == 404, "another file's owner token cannot delete")
    t.ok(t.c.request("DELETE", f"{API}/{a.id}", headers=a.bearer).status == 204
         and t.c.request("GET", f"{API}/{a.id}/meta").status == 404, "the owner token deletes, the file is gone")
    burn = t.ready(max_downloads=1)
    token = t.grant(burn).json()["token"]
    hidden = t.c.request("GET", f"{API}/{burn.id}/meta").status
    body = t.content(burn.id, token)
    after = t.c.request("GET", f"{API}/{burn.id}/meta").status
    t.ok(hidden == 404 and body.status == 200 and body.body == burn.content and after == 404,
         "the last permitted download still completes", f"{hidden} {body.status} {after}")
    # The metadata answers 404 for every file without downloads left, burned
    # or not; the owner token still finds a record that was not removed.
    gone = t.c.request("DELETE", f"{API}/{burn.id}", headers=burn.bearer).status
    t.ok(gone == 404, "the file is gone at once: its owner token finds no record", str(gone))


def check_upload(t):
    _, share = t.create()
    short = t.upload(share, share.content[:-1])
    long_ = t.upload(share, share.content + b"x")
    chunked = t.upload(share, [share.content, b"extra"])
    t.ok(short.status == 400 and long_.status == 400 and chunked.status == 400,
         "a body that differs from the declared size is refused", f"{short.status} {long_.status} {chunked.status}")
    t.ok(t.upload(share, [share.content[:10], share.content[10:]]).status == 204, "the exact size uploads after failed attempts")
    t.ok(t.upload(share).status == 409, "a second upload is refused and cannot replace the content")
    token = t.grant(share).json()["token"]
    t.ok(t.content(share.id, token).body == share.content, "the stored content is the first complete upload")


def check_lockout(t):
    target, other = t.ready(), t.ready()
    wrong = secrets.token_bytes(32)
    statuses = [t.grant(target, key=wrong).status for _ in range(5)]
    t.ok(statuses == [404] * 5, "five bad signatures each get the plain 404", str(statuses))
    live = t.c.request("GET", f"{API}/{target.id}/meta").status
    locked = t.grant(target)
    t.ok(live == 200 and locked.status == 404 and locked.body == NOT_FOUND,
         "the correct signature is refused while the file is locked, though the file is live",
         f"metadata {live}, download {locked.status}")
    t.ok(t.grant(other).status == 200, "the lock covers that one file only")


def set_cookies(response):
    """The Set-Cookie lines of a response, by cookie name."""
    return {line.split("=", 1)[0]: line for line in response.headers.get_all("Set-Cookie") or []}


def cookie_attributes(line):
    attrs = {}
    for part in line.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        attrs[key.lower()] = value
    return attrs


def attempt(t, body):
    """One sign-in; a 429 for the client's budget is waited out, one for a lockout is returned."""
    while True:
        r = t.c.json("POST", SESSION, body, wait=False)
        if r.code != "rate_limited":
            return r
        time.sleep(min(int(r.header("Retry-After") or 1), 60))


def check_accounts(t):
    acct = t.account()
    cookies = set_cookies(acct.signup)
    want = {"path": "/", "secure": "", "httponly": "", "samesite": "Strict"}
    for name, age in (("__Host-vault_session", "86400"), ("__Host-vault_device", "15552000")):
        attrs = cookie_attributes(cookies.get(name, ""))
        t.ok(all(attrs.get(k) == v for k, v in want.items()) and "domain" not in attrs and attrs.get("max-age") == age,
             f"{name} is Secure, HttpOnly, SameSite=Strict, for the whole origin and without a Domain",
             cookies.get(name, "missing"))
    t.ok(acct.signup.header("Cache-Control") == "no-store", "the sign-up answer, which carries a key, is not cached")
    r = t.c.request("GET", SESSION, headers=acct.headers())
    data = r.json() or {}
    t.ok(r.status == 200 and data.get("username") == acct.username and "sealed_key" not in data,
         "the cookie carries the session, whose answer leaves the sealed account key out", f"{r.status} {sorted(data)}")
    t.ok(t.c.request("GET", SESSION).status == 401, "without the cookie there is no session")

    ghost = "bb-" + secrets.token_hex(6)
    lookups = [t.c.json("POST", ACCOUNT + "/salt", {"username": name}) for name in (acct.username, ghost, ghost, ghost + "x")]
    salts = [(r.json() or {}).get("salt") if r.status == 200 else None for r in lookups]
    t.ok(salts[0] == b64(acct.salt) and salts[1] == salts[2] and salts[1] and len(unb64(salts[1])) == 16 and salts[1] != salts[3],
         "a username without an account gets a salt like one with: 16 bytes, the same each time", str(salts))
    bad = t.c.json("POST", ACCOUNT + "/salt", {"username": "Not A Name"})
    t.ok(bad.status == 400 and bad.code == "invalid_username", "a malformed username is refused", f"{bad.status} {bad.code}")
    wrong = attempt(t, {"username": acct.username, "auth": b64(secrets.token_bytes(32))})
    unknown = attempt(t, {"username": ghost, "auth": b64(secrets.token_bytes(32))})
    t.ok(wrong.status == unknown.status == 401 and wrong.body == unknown.body,
         "a wrong password and an unknown username get the same answer", f"{wrong.status} {unknown.status}")

    target = "bb-" + secrets.token_hex(6)
    statuses = [attempt(t, {"username": target, "auth": b64(secrets.token_bytes(32))}).status for _ in range(5)]
    locked = attempt(t, {"username": target, "auth": b64(secrets.token_bytes(32))})
    t.ok(statuses == [401] * 5 and locked.status == 429 and locked.code == "locked" and locked.header("Retry-After") == "900",
         "after five failures a client is refused that username for 15 minutes", f"{statuses} {locked.status} {locked.code}")

    before = acct.cookies.get("__Host-vault_session")
    t.ok(t.sign_in(acct).status == 200, "the lockout covers that username only")
    stale = t.c.request("GET", SESSION, headers={"Cookie": f"__Host-vault_session={before}"})
    t.ok(acct.cookies.get("__Host-vault_session") not in (None, before) and stale.status == 401,
         "signing in issues a new session and ends the one the browser held", f"stale {stale.status}")

    cross = t.c.json("POST", SESSION, {"username": acct.username, "auth": b64(acct.auth)}, {"Sec-Fetch-Site": "cross-site"})
    logout = t.c.request("DELETE", SESSION, headers=acct.headers({"Origin": "https://attacker.example"}))
    alive = t.c.request("GET", SESSION, headers=acct.headers())
    t.ok(cross.status == 403 and cross.code == "cross_origin" and not set_cookies(cross) and logout.status == 403 and alive.status == 200,
         "another site can neither sign a visitor in nor sign them out", f"{cross.status} {logout.status} {alive.status}")

    elsewhere = Account(acct.username)
    elsewhere.auth = acct.auth
    t.sign_in(elsewhere)
    salt, auth, sealed = secrets.token_bytes(16), secrets.token_bytes(32), secrets.token_bytes(60)
    changed = acct.absorb(t.c.json("POST", ACCOUNT + "/password", {
        "auth": b64(acct.auth), "salt": b64(salt), "new_auth": b64(auth), "sealed_key": b64(sealed),
    }, acct.headers()))
    if changed.status == 200:
        acct.salt, acct.auth, acct.sealed = salt, auth, sealed
    t.ok(changed.status == 200 and t.c.request("GET", SESSION, headers=elsewhere.headers()).status == 401
         and t.c.request("GET", SESSION, headers=acct.headers()).status == 200,
         "a password change ends the account's other sessions and renews this one", str(changed.status))

    held = acct.cookies.get("__Host-vault_session")
    out = acct.absorb(t.c.request("DELETE", SESSION, headers=acct.headers()))
    gone = t.c.request("GET", SESSION, headers={"Cookie": f"__Host-vault_session={held}"})
    t.ok(out.status == 204 and "__Host-vault_session" not in acct.cookies and gone.status == 401,
         "signing out ends the session and clears its cookie", str(out.status))
    t.sign_in(acct)


def check_totp(t):
    acct = t.account()
    setup = t.c.request("POST", ACCOUNT + "/totp/setup", headers=acct.headers())
    secret = (setup.json() or {}).get("secret", "")
    on = acct.absorb(t.c.json("POST", ACCOUNT + "/totp", {"auth": b64(acct.auth), "code": totp(secret)}, acct.headers()))
    data = on.json() or {}
    acct.recovery = list(data.get("recovery_codes", []))
    t.ok(setup.status == 200 and on.status == 200 and data.get("totp") is True and len(acct.recovery) == 10,
         "two-factor sign-in turns on with a code from the app, with ten recovery codes", f"{setup.status} {on.status}")

    def fresh():
        browser = Account(acct.username)
        browser.auth = acct.auth
        first = t.sign_in(browser)
        return browser, first, (first.json() or {}).get("ticket")

    browser, first, ticket = fresh()
    t.ok(first.status == 200 and (first.json() or {}).get("second_step") is True and not browser.cookies,
         "a right password alone gets a ticket and no cookie", str(first.status))
    code = totp(secret, 1)  # the step that turned it on is spent
    done = browser.absorb(t.c.json("POST", SESSION + "/totp", {"ticket": ticket, "code": code}, browser.headers()))
    t.ok(done.status == 200 and "__Host-vault_session" in browser.cookies, "the code completes the sign-in", str(done.status))
    _, _, other = fresh()
    replay = t.c.json("POST", SESSION + "/totp", {"ticket": other, "code": code})
    t.ok(replay.status == 401 and replay.code == "wrong_code", "the same code does not work twice", f"{replay.status} {replay.code}")
    reuse = t.c.json("POST", SESSION + "/totp", {"ticket": ticket, "code": totp(secret, 1)})
    t.ok(reuse.status == 401 and reuse.code == "ticket_expired", "a ticket serves one sign-in", f"{reuse.status} {reuse.code}")

    recovery = acct.recovery.pop(0)
    _, _, third = fresh()
    used = t.c.json("POST", SESSION + "/totp", {"ticket": third, "code": recovery})
    _, _, fourth = fresh()
    again = t.c.json("POST", SESSION + "/totp", {"ticket": fourth, "code": recovery})
    t.ok(used.status == 200 and (used.json() or {}).get("recovery_codes_left") == 9 and again.status == 401,
         "a recovery code signs in once", f"{used.status} {again.status}")
    sealed = t.c.request("GET", SESSION, headers=acct.headers())
    t.ok(sealed.status == 200 and (sealed.json() or {}).get("totp") is True, "the session reports two-factor sign-in as on")


def check_account_files(t):
    acct = t.account()
    share = t.ready()
    path = f"{ACCOUNT}/files/{share.id}"
    entry = b64(secrets.token_bytes(120))
    no_owner = t.c.json("PUT", path, {"entry": entry}, acct.headers())
    no_session = t.c.json("PUT", path, {"entry": entry}, share.bearer)
    kept = t.c.json("PUT", path, {"entry": entry}, acct.headers(share.bearer))
    t.ok(no_owner.status == 404 and no_session.status == 401 and kept.status == 204,
         "a file goes into an account only with both the session and its owner token",
         f"{no_owner.status} {no_session.status} {kept.status}")
    listing = t.c.request("GET", ACCOUNT + "/files", headers=acct.headers())
    files = (listing.json() or {}).get("files", [])
    t.ok(listing.status == 200 and listing.header("Cache-Control") == "no-store"
         and any(f.get("id") == share.id and f.get("entry") == entry for f in files),
         "the account lists it with the entry the browser sealed", str(listing.status))
    t.ok(t.c.request("GET", ACCOUNT + "/files").status == 401, "the list needs the session")


def check_rate_limit(t):
    def spoofed():
        ip = str(ipaddress.IPv4Address(secrets.randbits(32)))
        headers = {"X-Forwarded-For": ip, "X-Real-IP": ip, "Forwarded": f"for={ip}", "True-Client-IP": ip}
        return t.create(headers=headers, wait=False)

    accepted, refused = 0, None
    for _ in range(40):
        r, share = spoofed()
        if share:
            accepted += 1
        elif r.status == 429:
            refused = r
            break
    retry = refused.header("Retry-After") if refused else None
    t.ok(refused is not None and refused.code == "rate_limited" and retry and retry.isdigit(),
         "creates answer 429 with Retry-After once the client's bucket is empty", f"after {accepted}: {retry}")
    statuses = [spoofed()[0].status for _ in range(5)]
    t.ok(statuses == [429] * 5, "five more creates, each naming a new client address in forwarding headers, get 429 too",
         str(statuses))


def raw_exchange(t, request):
    """Sends raw bytes on a fresh connection; returns the first status line."""
    with t.c.raw_socket() as sock:
        sock.sendall(request)
        try:
            return sock.recv(4096).split(b"\r\n", 1)[0].decode(errors="replace")
        except (socket.timeout, OSError):
            return ""


def check_framing(t):
    """A request of ambiguous length must be refused before any handler runs.
    /healthz answers a well-framed POST with 405, so a 405 means it got through."""
    host = t.c.host.encode()

    def send(rest):
        return raw_exchange(t, b"POST /healthz HTTP/1.1\r\nHost: " + host + b"\r\n" + rest)

    control = send(b"Content-Length: 4\r\n\r\nabcd")
    t.ok(control.split(" ")[1:2] == ["405"], f"a well-framed POST to /healthz reaches the handler [{control}]")
    cases = (
        ("two different Content-Length values", b"Content-Length: 4\r\nContent-Length: 40\r\n\r\nabcd", ("400",)),
        ("a Transfer-Encoding with a space before the colon", b"Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n", ("400",)),
        ("an unsupported transfer coding", b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n", ("400", "501")),
    )
    for name, rest, codes in cases:
        line = send(rest)
        t.ok(line.split(" ")[1:2] and line.split(" ")[1] in codes, f"a request with {name} is refused before any handler [{line}]")


def check_host(t):
    r = t.c.request("GET", f"{API}/{random_id()}/meta", headers={"Host": "attacker.example"})
    answered = r.code not in (None, "misdirected")
    reflected = b"attacker.example" in r.body or any("attacker.example" in v for v in r.headers.values())
    t.ok(not answered and not reflected, f"the API does not answer for a foreign Host [{r.status} {r.code}]")


def check_slow_headers(t):
    for c in filter(None, (t.c, t.http)):
        elapsed = slow_headers(c)
        closed = f"closed after {elapsed:.0f} s" if elapsed is not None else "still open after 90 s"
        t.ok(elapsed is not None and elapsed <= 15,
             f"{c.origin}: a connection that never finishes its headers is closed within 15 s ({closed})")


def slow_headers(c, limit=90):
    """Seconds until the server gives up on headers sent one line a second."""
    with c.raw_socket() as sock:
        start = time.monotonic()
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {c.host}\r\n".encode())
        for i in range(limit):
            try:
                sock.sendall(f"X-Slow-{i}: x\r\n".encode())
                sock.settimeout(1)
                sock.recv(1024)  # an answer or the end of the stream: the server gave up
            except socket.timeout:
                continue
            except OSError:
                pass
            return time.monotonic() - start
    return None


CHECKS = [
    ("tls", check_tls), ("redirect", check_redirect), ("headers", check_headers), ("page", check_page),
    ("cache", check_cache), ("cors", check_cors), ("cross-site", check_cross_site), ("methods", check_methods),
    ("errors", check_errors), ("traversal", check_traversal), ("input", check_input),
    ("not-found", check_not_found), ("access", check_access), ("upload", check_upload),
    ("lockout", check_lockout), ("accounts", check_accounts), ("totp", check_totp),
    ("account-files", check_account_files), ("rate-limit", check_rate_limit), ("framing", check_framing),
    ("host", check_host), ("slow-headers", check_slow_headers),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base_url", help="origin of the instance, e.g. https://localhost")
    parser.add_argument("--cafile", help="CA certificate that signs the instance's TLS certificate")
    parser.add_argument("--http-url", help="plain HTTP origin that should redirect to base_url")
    parser.add_argument("--only", action="append", choices=[name for name, _ in CHECKS], help="run only these checks")
    parser.add_argument("--remote", action="store_true",
                        help="confirm that non-local targets are instances you operate. Limits count per client "
                             "address, so behind a proxy the instance does not trust, the rate-limit check spends "
                             "the create budget all clients share")
    args = parser.parse_args()

    for url in filter(None, (args.base_url, args.http_url)):
        host = urllib.parse.urlsplit(url).hostname or ""
        try:
            local = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local and not args.remote:
            sys.exit(f"{host} is not local; pass --remote if it is an instance you operate")

    t = Tester(Client(args.base_url, args.cafile), Client(args.http_url) if args.http_url else None)
    print(f"vault-share black-box checks against {args.base_url}")
    for name, check in CHECKS:
        if args.only and name not in args.only:
            continue
        t.check = name
        try:
            check(t)
        except Exception as e:  # report the broken check and go on with the rest
            t.report("FAIL", f"check stopped: {type(e).__name__}: {e}")
    t.check = "cleanup"
    try:
        failed = t.cleanup()
        t.ok(failed == 0, f"deletes the {len(t.shares)} test files and {len(t.accounts)} test account it created",
             f"{failed} could not be deleted")
    except Exception as e:
        t.report("FAIL", f"cleanup stopped: {type(e).__name__}: {e}")
    print(f"\n{t.counts['PASS']} passed, {t.counts['FAIL']} failed, {t.counts['SKIP']} skipped")
    sys.exit(1 if t.counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
