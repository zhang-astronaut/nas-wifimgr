"""HTTP 层测试：静态文件安全、CSRF、请求体上限、错误形状。

起一个真实的临时服务器（绑 127.0.0.1 随机端口），用 urllib 访问。
不依赖 nmcli —— 用 FakeBackend。
"""

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import api as apimod  # noqa: E402
from wifimgr import config  # noqa: E402
from wifimgr.api import Ctx, ScanCache  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.httpd import Handler, serve  # noqa: E402
from wifimgr.security import resolve_static  # noqa: E402
from wifimgr.store import Store  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "wifimgr", "static")


class _Log(object):
    def __getattr__(self, name):
        return lambda *a, **k: None


class TestStaticSecurity(unittest.TestCase):
    """目录穿越防护 —— resolve_static 是第一道闸。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        with open(os.path.join(self.dir, "index.html"), "w") as fh:
            fh.write("<html>ok</html>")
        os.mkdir(os.path.join(self.dir, "sub"))
        with open(os.path.join(self.dir, "sub", "a.js"), "w") as fh:
            fh.write("1")
        # 目录外放一个敏感文件
        self.outside = os.path.join(os.path.dirname(self.dir), "secret.txt")
        with open(self.outside, "w") as fh:
            fh.write("SECRET")

    def tearDown(self):
        self.tmp.cleanup()
        try:
            os.unlink(self.outside)
        except OSError:
            pass

    def test_ok_paths(self):
        self.assertIsNotNone(resolve_static(self.dir, "/index.html"))
        self.assertIsNotNone(resolve_static(self.dir, "/sub/a.js"))
        self.assertIsNotNone(resolve_static(self.dir, "/"))

    def test_traversal_blocked(self):
        for bad in (
            "/../secret.txt",
            "/../../etc/passwd",
            "/sub/../../secret.txt",
            "/%2e%2e/secret.txt",
            "/..%2fsecret.txt",
            "/sub/../../../etc/passwd",
        ):
            self.assertIsNone(resolve_static(self.dir, bad), "穿越未被拦截: %s" % bad)

    def test_null_byte_blocked(self):
        self.assertIsNone(resolve_static(self.dir, "/index.html\x00.txt"))

    def test_backslash_blocked(self):
        self.assertIsNone(resolve_static(self.dir, "/..\\secret.txt"))

    def test_absolute_escape_blocked(self):
        self.assertIsNone(resolve_static(self.dir, "//etc/passwd"))

    def test_nonexistent_returns_none(self):
        self.assertIsNone(resolve_static(self.dir, "/nope.html"))


class TestHttpServer(unittest.TestCase):
    """起真服务器验证端到端。"""

    @classmethod
    def setUpClass(cls):
        fake_mod.set_fixture_dir(FIXTURES)
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = config.load(None)
        cfg["http"]["listen_host"] = "127.0.0.1"
        cfg["http"]["listen_port"] = 0  # 让内核分配
        cfg["http"]["static_dir"] = STATIC
        cfg["http"]["csrf"]["enabled"] = True
        log = _Log()
        store = Store(os.path.join(cls.tmp.name, "t.db"))
        be = fake_mod.FakeBackend(cfg, log, scenario="connected")
        be.set_store(store)
        ctx = Ctx(cfg, be, store, log, guardian=None, scanner=ScanCache())
        cls.ctx = ctx
        cls.store = store
        cls.log = log

        import socketserver
        from wifimgr import httpd as httpd_mod
        from wifimgr.security import CsrfGuard

        Handler.ctx = ctx
        Handler.log = log
        Handler.static_dir = STATIC
        Handler.csrf = CsrfGuard(cfg)
        Handler.show_server_header = False
        ctx.csrf_token = Handler.csrf.token
        cls.server = httpd_mod._ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.store.close_all()
        cls.tmp.cleanup()

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def get(self, path, headers=None):
        req = urllib.request.Request(self.url(path), headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def test_session_sets_cookie(self):
        st, body, hdrs = self.get("/api/v1/session")
        self.assertEqual(st, 200)
        data = json.loads(body.decode())
        self.assertTrue(data["ok"])
        self.assertIn("csrf", data["data"])
        self.assertIn("Set-Cookie", hdrs)
        self.assertIn("SameSite=Strict", hdrs["Set-Cookie"])

    def test_security_headers_present(self):
        st, body, hdrs = self.get("/api/v1/status")
        self.assertEqual(hdrs.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(hdrs.get("X-Frame-Options"), "DENY")
        self.assertEqual(hdrs.get("Referrer-Policy"), "no-referrer")

    def test_scan_endpoint(self):
        st, body, _ = self.get("/api/v1/scan")
        self.assertEqual(st, 200)
        data = json.loads(body.decode())
        self.assertTrue(data["ok"])

    def test_unknown_api_404(self):
        st, body, _ = self.get("/api/v1/nope")
        self.assertEqual(st, 404)
        err = json.loads(body.decode())["error"]
        self.assertEqual(err["code"], "NOT_FOUND")

    def test_error_shape_consistent(self):
        st, body, _ = self.get("/api/v1/nope")
        err = json.loads(body.decode())["error"]
        for k in ("code", "message", "detail", "retryable", "hint", "request_id", "ts"):
            self.assertIn(k, err, "错误形状缺字段 %s" % k)

    def test_post_without_csrf_rejected(self):
        req = urllib.request.Request(
            self.url("/api/v1/scan"), data=b"{}", method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                st = resp.status
                body = resp.read()
        except urllib.error.HTTPError as e:
            st, body = e.code, e.read()
        self.assertEqual(st, 403, "无 CSRF token 应被拒")
        err = json.loads(body.decode())["error"]
        self.assertEqual(err["code"], "CSRF_FAILED")

    def test_post_with_csrf_ok(self):
        # 用 /disconnect 而不是 /scan：scan 有基于时间的限流，
        # 前面的用例可能已经把缓存填热，导致这里 429。
        # 每个用例都该独立，不依赖执行顺序。
        tok = self.ctx.csrf_token
        req = urllib.request.Request(
            self.url("/api/v1/disconnect"), data=b"{}", method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": tok,
                "Cookie": "wifimgr_csrf=%s" % tok,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                self.assertEqual(resp.status, 200)
        except urllib.error.HTTPError as e:
            # FakeBackend 的 disconnect 恒成功；若将来失败也不该是 CSRF/限流问题
            self.assertIn(e.code, (400,), "意外状态码 %s: %s" % (e.code, e.read()[:200]))
            body = json.loads(e.read().decode())
            self.assertNotEqual(body["error"]["code"], "CSRF_FAILED")

    def test_post_scan_with_csrf(self):
        """scan 需要先过限流窗口，这里显式重置缓存。"""
        self.ctx.scanner._scanned_at = 0.0
        self.ctx.scanner._items = []
        tok = self.ctx.csrf_token
        req = urllib.request.Request(
            self.url("/api/v1/scan"), data=b"{}", method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": tok,
                "Cookie": "wifimgr_csrf=%s" % tok,
            },
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode())
            self.assertTrue(body["ok"])
            self.assertTrue(body["data"]["items"])

    def test_body_too_large_rejected(self):
        tok = self.ctx.csrf_token
        big = json.dumps({"x": "a" * 40000}).encode()
        req = urllib.request.Request(
            self.url("/api/v1/connect"), data=big, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": tok,
                "Cookie": "wifimgr_csrf=%s" % tok,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                st = resp.status
        except urllib.error.HTTPError as e:
            st = e.code
        self.assertEqual(st, 400)

    def test_malformed_json_rejected(self):
        tok = self.ctx.csrf_token
        req = urllib.request.Request(
            self.url("/api/v1/scan"), data=b"{not json", method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": tok,
                "Cookie": "wifimgr_csrf=%s" % tok,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                st = resp.status
        except urllib.error.HTTPError as e:
            st = e.code
        self.assertEqual(st, 400)

    def test_static_index(self):
        st, body, hdrs = self.get("/")
        self.assertEqual(st, 200)
        self.assertIn("text/html", hdrs.get("Content-Type", ""))
        self.assertGreater(len(body), 0)

    def test_static_traversal_blocked(self):
        """用裸 socket 发未经规范化的路径（urllib 会在客户端侧先消解 ..，测不到）。"""
        import socket

        for raw_path in (
            b"/../../etc/passwd",
            b"/..%2f..%2fetc/passwd",
            b"/%2e%2e/%2e%2e/etc/passwd",
            b"/../../../../etc/shadow",
        ):
            req = (
                b"GET " + raw_path + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            try:
                s.sendall(req)
                chunks = []
                while True:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
            finally:
                s.close()
            data = b"".join(chunks)
            self.assertNotIn(b"root:", data, "泄漏了 /etc/passwd: %s" % raw_path)
            self.assertNotIn(b"root$:", data, "泄漏了 shadow: %s" % raw_path)
            status_line = data.split(b"\r\n", 1)[0]
            self.assertIn(b"404", status_line, "穿越尝试应 404 而非 200: %s" % status_line)

    def test_content_length_always_present(self):
        """HTTP/1.1 下缺 Content-Length 会让浏览器挂起。"""
        for p in ("/api/v1/status", "/api/v1/scan", "/api/v1/nope"):
            st, body, hdrs = self.get(p)
            self.assertIn("Content-Length", hdrs, "%s 缺 Content-Length" % p)

    def test_keepalive_multiple_requests(self):
        """连续请求同一连接：验证不残留垃圾数据。"""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        for _ in range(3):
            conn.request("GET", "/api/v1/status")
            resp = conn.getresponse()
            body = resp.read()
            self.assertEqual(resp.status, 200)
            self.assertTrue(json.loads(body.decode())["ok"])
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
