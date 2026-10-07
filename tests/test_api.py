"""API 层测试：直接调 handler 函数，不起 HTTP 服务器。"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import api as apimod  # noqa: E402
from wifimgr import config  # noqa: E402
from wifimgr.api import Ctx, ScanCache  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.daemon import Guardian  # noqa: E402
from wifimgr.errors import AppError, RateLimitedError, ValidationError  # noqa: E402
from wifimgr.store import Store  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SECRET = "MyS3cretPwd"


class _Log(object):
    def __init__(self):
        self.records = []

    def _r(self, lvl):
        def f(source, code, message, data=None):
            self.records.append((lvl, source, code, message, data or {}))

        return f

    def __getattr__(self, name):
        return self._r(name)


def mk_ctx(scenario="idle", tmpdir=None, with_guardian=True):
    fake_mod.set_fixture_dir(FIXTURES)
    cfg = config.load(None)
    cfg["http"]["static_dir"] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wifimgr", "static"
    )
    log = _Log()
    be = fake_mod.FakeBackend(cfg, log, scenario=scenario)
    store = Store(os.path.join(tmpdir, "t.db")) if tmpdir else None
    be.set_store(store)
    guardian = Guardian(cfg, be, store, log) if with_guardian else None
    ctx = Ctx(cfg, be, store, log, guardian=guardian, scanner=ScanCache())
    ctx.csrf_token = "test-token"
    return ctx, log, be, store


class TestSessionAndCaps(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_session(self):
        st, data = apimod.get_session(self.ctx)
        self.assertEqual(st, 200)
        self.assertEqual(data["csrf"], "test-token")
        self.assertEqual(data["backend"], "fake")
        self.assertIn("version", data)

    def test_capabilities_shape(self):
        st, data = apimod.get_capabilities(self.ctx)
        self.assertEqual(st, 200)
        for k in ("name", "can_scan", "can_connect", "sae_usable", "sae_evidence"):
            self.assertIn(k, data)

    def test_status(self):
        st, data = apimod.get_status(self.ctx)
        self.assertEqual(st, 200)
        self.assertIn("status", data)
        self.assertIn("connected", data["status"])


class TestScan(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_scan_returns_real_fixture_data(self):
        st, data = apimod.get_scan(self.ctx, query={"refresh": "1"})
        self.assertEqual(st, 200)
        self.assertEqual(len(data["items"]), 11, "应返回 wlan0 的 11 个网络")
        ssids = [i["ssid"] for i in data["items"]]
        self.assertIn("密码是八个八", ssids)
        self.assertIn("", ssids, "应保留隐藏网络")

    def test_hidden_network_display_label(self):
        st, data = apimod.get_scan(self.ctx, query={"refresh": "1"})
        hidden = [i for i in data["items"] if i["hidden"]]
        self.assertTrue(hidden)
        self.assertIn("隐藏网络", hidden[0]["display"])

    def test_rate_limit(self):
        apimod.get_scan(self.ctx, query={"refresh": "1"})  # 第一次，填充缓存
        with self.assertRaises(RateLimitedError) as cm:
            apimod.get_scan(self.ctx, query={"refresh": "1"})
        self.assertIn("retry_after", cm.exception.detail)

    def test_cold_cache_get_triggers_scan(self):
        """刚启动、缓存为空时，GET 也必须真的扫一次。

        回归测试：曾出现前端首屏空白 —— GET 直接返回空缓存而没触发扫描。
        """
        self.ctx.scanner._items = []
        self.ctx.scanner._scanned_at = 0.0
        st, data = apimod.get_scan(self.ctx, query={})  # 不带 refresh
        self.assertEqual(st, 200)
        self.assertTrue(data["items"], "冷缓存下 GET 必须触发一次扫描")

    def test_warm_cache_get_does_not_rescan(self):
        apimod.get_scan(self.ctx, query={"refresh": "1"})
        calls_before = len(self.be.calls)
        st, data = apimod.get_scan(self.ctx, query={})
        self.assertEqual(st, 200)
        self.assertEqual(len(self.be.calls), calls_before, "热缓存下 GET 不应再扫")
        self.assertTrue(data["items"])

    def test_post_scan_respects_rate_limit(self):
        apimod.get_scan(self.ctx, query={"refresh": "1"})
        with self.assertRaises(RateLimitedError):
            apimod.post_scan(self.ctx)

    def test_sae_flagged_in_mixed_network(self):
        st, data = apimod.get_scan(self.ctx, query={"refresh": "1"})
        mixed = [i for i in data["items"] if "sae" in (i["rsn_flags"] or "")]
        self.assertTrue(mixed, "应识别出声明 sae 的 AP")
        for i in mixed:
            self.assertEqual(i["auth_kind"], "mixed", "同时有 psk+sae 应判为 mixed")

    def test_scan_failure_returns_stale_cache(self):
        apimod.get_scan(self.ctx, query={"refresh": "1"})
        self.be.scenario = "wlan0_busy"
        self.ctx.scanner._scanned_at = 0.0  # 允许再扫
        st, data = apimod.get_scan(self.ctx, query={"refresh": "1"})
        self.assertEqual(st, 200)
        self.assertTrue(data["stale"], "失败时应标记 stale")
        self.assertTrue(data["items"], "应回退到上次缓存")


class TestConnect(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_connect_success(self):
        st, data = apimod.post_connect(
            self.ctx,
            body={"ssid": "密码是八个八", "bssid": "50:4F:3B:18:31:9B", "password": SECRET,
                  "auth_kind": "mixed", "bssid_lock": True},
        )
        self.assertEqual(st, 200)
        self.assertTrue(data["result"]["ok"])
        self.assertEqual(data["result"]["ip"], "192.168.31.64")

    def test_connect_password_never_in_log(self):
        apimod.post_connect(
            self.ctx,
            body={"ssid": "MyNet", "password": SECRET, "auth_kind": "psk"},
        )
        blob = json.dumps(self.log.records, ensure_ascii=False, default=str)
        self.assertNotIn(SECRET, blob, "密码泄漏进日志")

    def test_connect_password_never_in_response(self):
        st, data = apimod.post_connect(
            self.ctx, body={"ssid": "MyNet", "password": SECRET, "auth_kind": "psk"}
        )
        self.assertNotIn(SECRET, json.dumps(data, ensure_ascii=False, default=str))

    def test_connect_missing_password_rejected(self):
        with self.assertRaises(ValidationError):
            apimod.post_connect(self.ctx, body={"ssid": "MyNet", "auth_kind": "psk"})

    def test_connect_empty_ssid_rejected(self):
        with self.assertRaises(ValidationError):
            apimod.post_connect(self.ctx, body={"ssid": "", "password": SECRET})

    def test_wrong_password_returns_400_and_explains(self):
        self.be.scenario = "wrong_password"
        st, data = apimod.post_connect(
            self.ctx, body={"ssid": "MyNet", "password": SECRET, "auth_kind": "psk"}
        )
        self.assertEqual(st, 400)
        res = data["result"]
        self.assertFalse(res["ok"])
        self.assertEqual(res["phase"], "accepted_but_handshake_failed")
        self.assertIn("密码", res["message"])

    def test_attempt_recorded(self):
        apimod.post_connect(
            self.ctx, body={"ssid": "MyNet", "password": SECRET, "auth_kind": "psk"}
        )
        rows = self.store.list_attempts(5)
        self.assertTrue(rows)
        self.assertNotIn(SECRET, json.dumps(rows, ensure_ascii=False, default=str))


class TestNetworksCrud(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_save_then_list_has_no_password(self):
        st, data = apimod.put_network(
            self.ctx,
            body={"profile_name": "net1", "ssid": "MyNet", "password": SECRET, "key_mgmt": "wpa-psk"},
        )
        self.assertEqual(st, 200)
        st, data = apimod.get_networks(self.ctx)
        blob = json.dumps(data, ensure_ascii=False, default=str)
        self.assertNotIn(SECRET, blob, "列表接口泄漏密码")
        self.assertTrue(data["items"][0]["has_secret"])
        self.assertNotIn("password", data["items"][0])

    def test_delete_unmanaged_rejected(self):
        with self.assertRaises(ValidationError):
            apimod.delete_network(self.ctx, query={"profile_name": "RD08_IoT"})

    def test_delete_managed(self):
        apimod.put_network(
            self.ctx,
            body={"profile_name": "net1", "ssid": "MyNet", "password": SECRET, "key_mgmt": "wpa-psk"},
        )
        st, data = apimod.delete_network(self.ctx, query={"profile_name": "net1"})
        self.assertTrue(data["deleted"])

    def test_network_connect(self):
        apimod.put_network(
            self.ctx,
            body={"profile_name": "net1", "ssid": "MyNet", "password": SECRET, "key_mgmt": "wpa-psk"},
        )
        st, data = apimod.post_network_connect(self.ctx, query={"profile_name": "net1"})
        self.assertEqual(st, 200)

    def test_network_connect_missing(self):
        from wifimgr.errors import NotFoundError

        with self.assertRaises(NotFoundError):
            apimod.post_network_connect(self.ctx, query={"profile_name": "nope"})


class TestDaemonApi(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_get_daemon(self):
        st, data = apimod.get_daemon(self.ctx)
        self.assertEqual(st, 200)
        self.assertIn("config", data)
        self.assertIn("interval_sec", data["config"])
        self.assertIn("backoff", data["config"])

    def test_put_daemon_partial(self):
        st, data = apimod.put_daemon(self.ctx, body={"interval_sec": 30, "max_retries": 9})
        self.assertEqual(st, 200)
        self.assertEqual(data["config"]["interval_sec"], 30)
        self.assertEqual(data["config"]["max_retries"], 9)

    def test_put_daemon_invalid(self):
        with self.assertRaises(ValueError):
            apimod.put_daemon(self.ctx, body={"interval_sec": 1})


class TestEventsAndDoctor(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ctx, self.log, self.be, self.store = mk_ctx(tmpdir=self._t.name)

    def tearDown(self):
        if self.store:
            self.store.close_all()
        self._t.cleanup()

    def test_events_shape(self):
        self.store.add_event({"ts": 1.0, "level": "info", "source": "t", "code": "c", "message": "m", "data": {}})
        st, data = apimod.get_events(self.ctx, query={"limit": "10"})
        self.assertEqual(st, 200)
        self.assertIn("items", data)
        self.assertIn("next_since", data)

    def test_doctor_shape(self):
        st, data = apimod.get_doctor(self.ctx)
        self.assertEqual(st, 200)
        self.assertIn("checks", data)
        self.assertTrue(data["checks"])
        for c in data["checks"]:
            self.assertIn("name", c)
            self.assertIn("ok", c)


if __name__ == "__main__":
    unittest.main(verbosity=2)
