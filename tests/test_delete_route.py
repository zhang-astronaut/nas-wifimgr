"""删除已保存网络（DELETE /api/v1/networks/<profile>）端到端回归测试。

背景：用户报告点删除按钮报「无此接口: DELETE /api/v1/networks/%E5%AF%86...」。
根因是 httpd._match_deep() 里的 DELETE 分支被误写在 `if method == "POST"`
之内 —— 代码存在但永远不可达，任何 DELETE 都落到 404。

这个文件的写法刻意遵守两条教训：
  1. **起真服务器、走真路由**，而不是直接调 _match_deep()。路由 bug 只有
     经过「method + path -> ROUTES/_match_deep」这条真实链路才暴露得出来。
  2. **用真实的 Store + 真实的 profile 名**（URL 编码的中文 + 连字符），
     因为上一个「记住网络不生效」的 bug 正是因为测试全用 mock，
     真实注入路径从未被测过。
"""

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import config  # noqa: E402
from wifimgr.api import Ctx, ScanCache, delete_network  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.errors import AppError  # noqa: E402
from wifimgr.httpd import Handler  # noqa: E402
from wifimgr.security import CsrfGuard  # noqa: E402
from wifimgr.store import Store  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "wifimgr", "static")

# 取自用户实际报错的 URL：中文 SSID + 连字符 + 数字后缀
REAL_PROFILE = "密码是八个八wifi5-18319B"
REAL_ENCODED = urllib.parse.quote(REAL_PROFILE, safe="")


class _Log(object):
    def __getattr__(self, name):
        return lambda *a, **k: None


class TestDeleteNetworkRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_mod.set_fixture_dir(FIXTURES)
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = config.load(None)
        cfg["http"]["listen_host"] = "127.0.0.1"
        cfg["http"]["listen_port"] = 0
        cfg["http"]["static_dir"] = STATIC
        cfg["http"]["csrf"]["enabled"] = True

        log = _Log()
        store = Store(os.path.join(cls.tmp.name, "t.db"))
        be = fake_mod.FakeBackend(cfg, log, scenario="connected")
        be.set_store(store)
        ctx = Ctx(cfg, be, store, log, guardian=None, scanner=ScanCache())

        from wifimgr import httpd as httpd_mod

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

        cls.ctx = ctx
        cls.store = store
        cls.tok = ctx.csrf_token

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.store.close_all()
        cls.tmp.cleanup()

    def _req(self, method, path, data=None, headers=None):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=data,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _csrf_headers(self):
        return {
            "Content-Type": "application/json",
            "X-CSRF-Token": self.tok,
            "Cookie": "wifimgr_csrf=%s" % self.tok,
        }

    def _seed(self, name=REAL_PROFILE):
        """把 profile 登记为本应用管理的，并建立 saved_network 记录。"""
        self.store.upsert_profile_ref(
            name, uuid="fake-uuid-1", managed=True, key_mgmt="wpa-psk", has_psk=True
        )
        self.store.upsert_saved_network(
            profile_name=name,
            ssid="密码是八个八wifi5",
            uuid="fake-uuid-1",
            key_mgmt="wpa-psk",
            security="WPA2",
        )
        return name

    # ---------- 核心回归 ----------

    def test_delete_deep_route_not_404(self):
        """这就是用户报的那个 404。必须 200，且不能是 NOT_FOUND。"""
        self._seed()
        st, body = self._req(
            "DELETE",
            "/api/v1/networks/" + REAL_ENCODED,
            headers=self._csrf_headers(),
        )
        self.assertNotEqual(st, 404, "DELETE 仍然 404 —— _match_deep 的 DELETE 分支不可达")
        if st != 200:
            payload = json.loads(body.decode())
            raise AssertionError(
                "期望 200，得到 %s: %s" % (st, payload.get("error", {}).get("message"))
            )
        data = json.loads(body.decode())
        self.assertTrue(data["ok"])
        self.assertTrue(data["data"]["deleted"])

    def test_delete_actually_removes_records(self):
        """路由通了还不够：要真的把记录删掉，否则前端刷新后还会显示。"""
        name = self._seed("待删除-A")
        self.assertTrue(self.store.is_managed(name))
        self.assertIsNotNone(self.store.get_saved_network(name))
        st, _ = self._req(
            "DELETE",
            "/api/v1/networks/" + urllib.parse.quote(name, safe=""),
            headers=self._csrf_headers(),
        )
        self.assertEqual(st, 200)
        self.assertFalse(self.store.is_managed(name), "profile_ref 残留，列表会重复显示")
        self.assertIsNone(
            self.store.get_saved_network(name), "saved_network 残留，刷新后还在"
        )

    def test_error_is_not_notfound_code(self):
        """失败时也不该回落到 404「无此接口」——那是路由缺失，不是业务拒绝。"""
        st, body = self._req(
            "DELETE", "/api/v1/networks/" + REAL_ENCODED, headers=self._csrf_headers()
        )
        err = json.loads(body.decode()).get("error", {})
        self.assertNotEqual(err.get("code"), "NOT_FOUND")
        self.assertNotIn("无此接口", err.get("message", ""))

    # ---------- 相邻行为不能被改坏 ----------

    def test_post_connect_route_still_works(self):
        """同一个 _match_deep，POST /connect 分支不能被这次改动带坏。"""
        from wifimgr.httpd import _match_deep

        h = _match_deep(("POST", "/api/v1/networks/" + REAL_ENCODED + "/connect"))
        self.assertIsNotNone(h, "POST /connect 分支被误伤")

    def test_post_networks_connect_route_still_works(self):
        """POST /networks/connect 是 ROUTES 里的静态路由，不走 _match_deep。"""
        from wifimgr import api as apimod

        self.assertIs(apimod.ROUTES.get(("POST", "/api/v1/networks/connect")), apimod.post_network_connect)
        self.assertIs(apimod.ROUTES.get(("DELETE", "/api/v1/networks")), apimod.delete_network)

    def test_delete_without_csrf_rejected(self):
        """路由通了不代表能绕过 CSRF。"""
        self._seed()
        st, body = self._req("DELETE", "/api/v1/networks/" + REAL_ENCODED)
        self.assertEqual(st, 403)
        err = json.loads(body.decode())["error"]
        self.assertEqual(err["code"], "CSRF_FAILED")

    def test_delete_unmanaged_profile_refused(self):
        """非本应用创建的 profile 必须拒绝删除（业务校验仍在路由之后生效）。"""
        name = "系统自带-profile"
        self.store.upsert_profile_ref(name, uuid="x", managed=False)
        st, body = self._req(
            "DELETE",
            "/api/v1/networks/" + urllib.parse.quote(name, safe=""),
            headers=self._csrf_headers(),
        )
        self.assertNotEqual(st, 200, "非托管 profile 不该被删成功")
        self.assertTrue(self.store.is_managed(name) is False)

    def test_delete_get_still_404(self):
        """DELETE 专属路径不能被 GET 复用。"""
        st, _ = self._req("GET", "/api/v1/networks/" + REAL_ENCODED)
        self.assertEqual(st, 404)

    def test_delete_with_slash_in_name_is_rejected_not_traversal(self):
        """名字里含编码斜杠 %2F 时必须被拒绝。

        注意这里期望的是 4xx 拒绝而非 404：``%2F`` 在原始 path 里不是斜杠，
        所以正则 ``[^/]+`` 会匹配上，unquote 后得到 "a/b"。这本身不是漏洞——
        ``delete_profile`` 只把名字作为 argv 传给 nmcli，不参与任何路径拼接，
        且 ``delete_network`` 先跑 ``store.is_managed()``，非托管 profile 直接拒绝。
        真正要守住的是「不被当成路径穿越」，不是状态码。
        """
        st, body = self._req(
            "DELETE",
            "/api/v1/networks/a%2Fb",
            headers=self._csrf_headers(),
        )
        self.assertIn(st, (400, 404), "含斜杠的名字应被拒绝，得到 %s" % st)
        err = json.loads(body.decode()).get("error", {})
        self.assertNotEqual(err.get("code"), "INTERNAL", "不该把非法名字漏到后端炸掉")
        # 确认没有在磁盘上产生 a/b 相关的副作用
        self.assertFalse(self.store.is_managed("a/b"))


class TestDeleteActiveProtection(unittest.TestCase):
    """删除当前正在使用的 profile 会直接掉线 WiFi —— 必须拦住。

    这条保护是实机事故换来的：误删活跃 profile 后 wlan0 立刻 disconnected，
    而守护线程会接着尝试重连，把 profile 重建成 key-mgmt=none 的坏状态，
    反而比删除前更难恢复。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = config.load(None)
        self.log = _Log()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.backend = fake_mod.FakeBackend(cfg, self.log, scenario="connected")
        self.backend.set_store(self.store)
        self.ctx = Ctx(cfg, self.backend, self.store, self.log,
                       guardian=None, scanner=ScanCache())
        # FakeBackend 在 connected 场景下活跃 profile 就是这个名字
        self.active = self.ctx.active_profile_name()
        self.assertTrue(self.active, "FakeBackend 应能给出活跃 profile 名")

    def tearDown(self):
        self.store.close_all()
        # Windows 上 sqlite 连接可能还被threadobject 持有，
        # TemporaryDirectory.cleanup() 会因文件占用抛 WinError 32。
        # 清理失败不该让测试失败 —— 临时目录由系统回收。
        try:
            self.tmp.cleanup()
        except OSError:
            pass

    def _seed(self, name):
        self.store.upsert_profile_ref(name, uuid="u", managed=True,
                                      key_mgmt="wpa-psk", has_psk=True)
        self.store.upsert_saved_network(profile_name=name, ssid="x",
                                        key_mgmt="wpa-psk", security="WPA2")

    def test_active_profile_cannot_be_deleted(self):
        self._seed(self.active)
        # 先把该 profile 放进 FakeBackend，这样「没被删」才有意义
        self.backend._profiles[self.active] = {"psk": "x", "uuid": "u"}
        with self.assertRaises(AppError) as cm:
            delete_network(self.ctx, query={"profile_name": self.active})
        self.assertEqual(cm.exception.code, "VALIDATION_FAILED")
        self.assertIn("正在使用", cm.exception.message)
        # 关键：什么都没被删
        self.assertTrue(self.store.is_managed(self.active),
                        "被拦下时不应删除数据库记录")
        self.assertIn(self.active, self.backend._profiles,
                      "被拦下时不应删除 NM profile")

    def test_other_profile_still_deletable(self):
        """保护不能误伤：非活跃的记录必须照常能删。"""
        other = "另一个网络-1234"
        self._seed(other)
        self.backend._profiles[other] = {"psk": "x"}
        status, payload = delete_network(self.ctx, query={"profile_name": other})
        self.assertEqual(status, 200)
        self.assertTrue(payload["deleted"])
        self.assertFalse(self.store.is_managed(other))

    def test_status_failure_does_not_block_delete(self):
        """取不到活跃 profile 时必须放行 —— 宁可误删也不要卡住用户。

        取不到活跃信息是可能发生的（nmcli 超时、iw 缺失等）。
        把删除完全堵死会让功能变成不可用。
        """
        self._seed("可删-9999")
        self.backend._profiles["可删-9999"] = {"psk": "x"}

        def boom():
            raise RuntimeError("nmcli 超时")

        self.backend.status = boom
        status, payload = delete_network(self.ctx, query={"profile_name": "可删-9999"})
        self.assertEqual(status, 200, "status 挂掉时不该阻塞删除")
        self.assertTrue(payload["deleted"])

    def test_no_active_profile_still_deletable(self):
        """未连接时 active 为 None，任何 profile 都应可删。"""
        self.backend._active = ""
        self.backend.scenario = "disconnected"
        name = "离线时的网络-1"
        self._seed(name)
        self.backend._profiles[name] = {"psk": "x"}
        status, payload = delete_network(self.ctx, query={"profile_name": name})
        self.assertEqual(status, 200)


class TestMatchDeepUnit(unittest.TestCase):
    """纯单元层：把方法名写死，防止再有人把分支缩进回 POST 里面。"""

    def test_delete_branch_reachable(self):
        from wifimgr.httpd import _match_deep

        self.assertIsNotNone(_match_deep(("DELETE", "/api/v1/networks/foo")))

    def test_post_branch_reachable(self):
        from wifimgr.httpd import _match_deep

        self.assertIsNotNone(_match_deep(("POST", "/api/v1/networks/foo/connect")))

    def test_other_methods_rejected(self):
        from wifimgr.httpd import _match_deep

        for m in ("GET", "PUT", "PATCH"):
            self.assertIsNone(_match_deep((m, "/api/v1/networks/foo")), m)


if __name__ == "__main__":
    unittest.main(verbosity=2)