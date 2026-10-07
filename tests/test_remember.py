"""「记住网络」链路测试。

起因：用户勾选了「保存此网络」，连接成功，但 UI「已保存的网络」永远显示
「还没有保存的网络」。查 DB 发现 saved_network / profile_ref 都是 0 行，
而 connect_attempt 有 4 条 activated 记录 —— 说明连接成功但入库被静默跳过。

三个叠加缺陷：
  1. ``NMBackend`` 没有 ``set_store``，``__main__`` 的
     ``hasattr(backend, "set_store")`` 恒为 False -> store 永不注入
  2. ``connect()`` 调 ``apply_profile`` 时没传 store -> 那条入库分支也跳过
  3. ``_store_remember`` 在 store 为 None 时静默 return，无任何日志

这里用**真实的 NMBackend + 假 store** 组合复现并锁定回归。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import config, nmkey  # noqa: E402
from wifimgr.backends.nmcli import NMBackend  # noqa: E402
from wifimgr.models import ConnectRequest  # noqa: E402


class _Log(object):
    def __init__(self):
        self.records = []

    def _r(self, lvl):
        def f(source, code, message, data=None):
            self.records.append((lvl, source, code, message, data or {}))

        return f

    def __getattr__(self, name):
        return self._r(name)

    def codes(self):
        return [r[2] for r in self.records]


class _StubResult(object):
    def __init__(self, stdout="", rc=0, stderr=""):
        self.stdout = stdout
        self.rc = rc
        self.stderr = stderr
        self.timed_out = False
        self.elapsed_ms = 1

    @property
    def ok(self):
        return self.rc == 0

    def to_dict(self, secrets=()):
        return {}


class TestStoreInjection(unittest.TestCase):
    """缺陷 1：NMBackend 必须有 set_store。"""

    def setUp(self):
        self.cfg = config.load(None)
        self.log = _Log()
        self.be = NMBackend(self.cfg, self.log, nmcli="/usr/bin/nmcli")

    def test_has_set_store_method(self):
        """__main__ 用 hasattr(backend,'set_store') 判断，缺了就静默跳过注入。"""
        self.assertTrue(hasattr(self.be, "set_store"), "NMBackend 缺少 set_store")

    def test_store_defaults_to_none(self):
        self.assertIsNone(self.be.store)

    def test_set_store_assigns(self):
        sentinel = object()
        self.be.set_store(sentinel)
        self.assertIs(self.be.store, sentinel)


class TestRememberChain(unittest.TestCase):
    """缺陷 2+3：remember=True 必须真的入库。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keydir = os.path.join(self.tmp.name, "keys")
        os.makedirs(self.keydir)
        self.cfg = config.load(None)
        self.log = _Log()
        self.be = NMBackend(
            self.cfg, self.log, nmcli="/usr/bin/nmcli", keyfiles_dir=self.keydir
        )

        # 记录调用
        self.calls = []
        self.written = {}

        def fake_nm(args, timeout=15, lock=False):
            argv = list(args)
            self.calls.append(argv)
            # apply_profile 的回读校验
            if argv[:2] == ["-g", "connection.uuid"]:
                name = argv[-1]
                return _StubResult(self.written.get(name, {}).get("uuid", ""))
            if argv[:2] == ["-g", "802-11-wireless.ssid"]:
                name = argv[-1]
                return _StubResult(self.written.get(name, {}).get("ssid", ""))
            if argv[:2] == ["-g", "802-11-wireless-security.key-mgmt"]:
                name = argv[-1]
                return _StubResult(self.written.get(name, {}).get("key_mgmt", ""))
            if argv[:2] == ["-g", "802-11-wireless.bssid"]:
                name = argv[-1]
                return _StubResult(self.written.get(name, {}).get("bssid", ""))
            if argv[:2] == ["connection", "up"]:
                return _StubResult("")
            if argv[:2] == ["connection", "reload"]:
                return _StubResult("")
            if argv[:2] == ["-f", "GENERAL.STATE"]:
                return _StubResult("GENERAL.STATE:  100 (connected)")
            if argv[:2] == ["-t", "-f"]:
                return _StubResult("")
            return _StubResult("")

        self.be._nm = fake_nm
        self.be.status = lambda: _FakeStatus()
        self.be.capabilities = lambda: _FakeCaps()
        # apply_profile 会真的写 keyfile —— 记录内容以便断言
        orig_apply = self.be.apply_profile

        def apply_and_record(*a, **kw):
            name = kw.get("profile_name") or a[0]
            self.written[name] = {
                "uuid": nmkey.stable_uuid(name),
                "ssid": kw.get("ssid") or (a[1] if len(a) > 1 else ""),
                "key_mgmt": kw.get("key_mgmt") or (a[3] if len(a) > 3 else "wpa-psk"),
                "bssid": kw.get("bssid") or (a[4] if len(a) > 4 else ""),
            }
            return orig_apply(*a, **kw)

        self.be.apply_profile = apply_and_record

    def tearDown(self):
        self.tmp.cleanup()

    def test_remember_true_populates_saved_network(self):
        """核心回归：remember=True 且 store 已注入 -> saved_network 有记录。"""
        from wifimgr.store import Store

        store = Store(os.path.join(self.tmp.name, "t.db"))
        try:
            self.be.set_store(store)
            req = ConnectRequest(
                ssid="MyNet", bssid="AA:BB:CC:DD:EE:FF",
                password="12345678", auth_kind="psk", remember=True,
            )
            res = self.be.connect(req)
            self.assertTrue(res.ok, "连接应成功: %s" % res.message)
            rows = store.list_saved_networks()
            self.assertEqual(len(rows), 1, "remember=True 应写入 saved_network")
            self.assertEqual(rows[0]["ssid"], "MyNet")
            self.assertEqual(rows[0]["connect_count"], 1)
            # profile_ref 也应有，且 managed=1（删除保护依赖它）
            ref = store.get_profile_ref(rows[0]["profile_name"])
            self.assertIsNotNone(ref, "profile_ref 未写入")
            self.assertEqual(ref["managed"], 1)
            # 结果里不应有保存失败的警告
            self.assertNotIn("remember_warning", res.detail)
        finally:
            store.close_all()

    def test_remember_false_does_not_persist(self):
        """不勾选保存时不应写库（但 keyfile 仍会写，NM 侧 profile 保留）。"""
        from wifimgr.store import Store

        store = Store(os.path.join(self.tmp.name, "t2.db"))
        try:
            self.be.set_store(store)
            req = ConnectRequest(
                ssid="OtherNet", password="12345678", auth_kind="psk", remember=False
            )
            res = self.be.connect(req)
            self.assertTrue(res.ok)
            self.assertEqual(store.list_saved_networks(), [])
        finally:
            store.close_all()

    def test_store_none_is_logged_loudly(self):
        """缺陷 3：store 缺失必须留日志，不能静默 return。"""
        req = ConnectRequest(
            ssid="MyNet", password="12345678", auth_kind="psk", remember=True
        )
        res = self.be.connect(req)
        self.assertTrue(res.ok)
        # 必须有 error 级别日志
        errs = [r for r in self.log.records if r[0] == "error"]
        self.assertTrue(errs, "store 缺失时应有 error 日志")
        self.assertIn("remember.no_store", self.log.codes())
        # 且结果里带 warning，让前端能提示用户
        self.assertIn("remember_warning", res.detail)

    def test_apply_profile_receives_store(self):
        """缺陷 2：connect() 必须把 store 传给 apply_profile。"""
        from wifimgr.store import Store

        store = Store(os.path.join(self.tmp.name, "t3.db"))
        try:
            seen = {}
            orig = self.be.apply_profile

            def spy(*a, **kw):
                seen.update(kw)
                return orig(*a, **kw)

            self.be.apply_profile = spy
            self.be.set_store(store)
            req = ConnectRequest(
                ssid="MyNet", password="12345678", auth_kind="psk", remember=True
            )
            self.be.connect(req)
            self.assertIn("store", seen, "connect() 未向 apply_profile 传 store")
            self.assertIs(seen["store"], store, "传给 apply_profile 的不是同一个 store")
        finally:
            store.close_all()

    def test_keyfile_written_regardless(self):
        """无论 remember 与否，keyfile 都要写（否则下次无法一键重连）。"""
        req = ConnectRequest(
            ssid="MyNet", password="12345678", auth_kind="psk", remember=False
        )
        self.be.connect(req)
        files = os.listdir(self.keydir)
        self.assertEqual(len(files), 1, "应生成 1 个 keyfile，实际: %s" % files)
        body = open(os.path.join(self.keydir, files[0]), encoding="utf-8").read()
        self.assertIn("psk=12345678", body, "keyfile 应含密码（0600 root）")
        self.assertIn("type=wifi", body)


class _FakeStatus(object):
    connected = True
    source = "nm_active"
    confidence = 1.0
    ssid = "MyNet"
    bssid = "AA:BB:CC:DD:EE:FF"
    profile_name = "MyNet"
    iface = "wlan0"
    ip = "192.168.31.64"
    signal = -50
    state = "connected"
    detail = {}

    def to_dict(self):
        return {"connected": self.connected, "ssid": self.ssid}


class _FakeCaps(object):
    name = "nmcli"
    sae_configurable = False
    sae_evidence = []
    notes = []


if __name__ == "__main__":
    unittest.main(verbosity=2)
