"""守护线程测试：退避计算、宽限期、抖动检测、dry_run、锁。"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import config  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.daemon import Guardian, backoff_delay  # noqa: E402
from wifimgr.store import Store  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class _Log(object):
    def __init__(self):
        self.records = []

    def _r(self, lvl):
        def f(source, code, message, data=None):
            self.records.append((lvl, source, code, message, data or {}))

        return f

    def __getattr__(self, name):
        return self._r(name)


class _Rng(object):
    """确定性 RNG：始终返回区间中点。"""

    def __init__(self):
        self.calls = 0

    def uniform(self, a, b):
        self.calls += 1
        return (a + b) / 2.0

    def __call__(self):
        return self


class TestBackoff(unittest.TestCase):
    def test_growth(self):
        vals = [
            backoff_delay(i, base_sec=5, factor=2.0, cap_sec=300, jitter=0, rng=_Rng())
            for i in range(1, 9)
        ]
        self.assertEqual(vals, [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 300.0])

    def test_capped(self):
        for i in (7, 8, 20):
            v = backoff_delay(i, 5, 2.0, 300, 0, rng=_Rng())
            self.assertLessEqual(v, 300.0)

    def test_jitter_within_bounds(self):
        for i in range(1, 10):
            base = min(5 * (2 ** (i - 1)), 300.0)
            v = backoff_delay(i, 5, 2.0, 300, 0.2, rng=_Rng())
            self.assertGreaterEqual(v, base * 0.8 - 0.01)
            self.assertLessEqual(v, base * 1.2 + 0.01)

    def test_attempt_below_one_clamped(self):
        self.assertEqual(backoff_delay(0, 5, 2.0, 300, 0, rng=_Rng()), 5.0)
        self.assertEqual(backoff_delay(-5, 5, 2.0, 300, 0, rng=_Rng()), 5.0)

    def test_factor_one_is_constant(self):
        vals = [backoff_delay(i, 7, 1.0, 300, 0, rng=_Rng()) for i in range(1, 6)]
        self.assertEqual(vals, [7.0] * 5)


def _mk(scenario="idle", tmpdir=None, daemon_over=None):
    fake_mod.set_fixture_dir(FIXTURES)
    cfg = config.load(None)
    if daemon_over:
        cfg["daemon"].update(daemon_over)
    log = _Log()
    be = fake_mod.FakeBackend(cfg, log, scenario=scenario)
    store = Store(os.path.join(tmpdir, "t.db")) if tmpdir else None
    return cfg, log, be, store


class TestGuardianCycle(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmp.name

    def tearDown(self):
        if getattr(self, "store", None):
            self.store.close_all()
        self._tmp.cleanup()

    def test_healthy_no_action(self):
        """已连接时不做任何动作。"""
        cfg, log, be, store = _mk(scenario="connected", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        ok, attempted, detail = g.run_once()
        self.assertTrue(ok)
        self.assertFalse(attempted, "已连接时不应有动作")
        self.assertEqual(detail["reason"], "already_connected")

    def test_dry_run_no_action(self):
        """dry_run 下断开也不动作，但要留下日志说明原因。"""
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = True
        g._active_profile = "RD08_IoT"
        ok, attempted, detail = g.run_once()
        self.assertFalse(ok)
        self.assertFalse(attempted, "dry_run 不应动作")
        self.assertEqual(detail["reason"], "dry_run")

    def test_no_profile_no_action(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        g._active_profile = ""
        g._fallback_profile = ""
        ok, attempted, detail = g.run_once()
        self.assertFalse(ok)
        self.assertFalse(attempted)
        self.assertEqual(detail["reason"], "no_profile")

    def test_reconnect_uses_active_profile(self):
        """守护应调用 activate_profile(配置的 profile)，而非自己挑一个。"""
        cfg, log, be, store = _mk(scenario="wrong_password", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        g._active_profile = "RD08_IoT"
        ok, attempted, detail = g.run_once()
        self.assertFalse(ok, "wrong_password 场景下重连应失败")
        self.assertTrue(attempted, "应执行了重连动作")
        self.assertIn(("connection", "up", "RD08_IoT"), be.calls)
        # 失败应落库
        self.assertTrue(store.list_attempts(5), "失败尝试应入库")

    def test_reconnect_success_records(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        g._active_profile = "RD08_IoT"
        store.upsert_saved_network(profile_name="RD08_IoT", ssid="RD08_IoT", key_mgmt="wpa-psk")
        ok, attempted, detail = g.run_once()
        self.assertTrue(ok)
        self.assertTrue(attempted)
        self.assertEqual(store.get_saved_network("RD08_IoT")["connect_count"], 1)

    def test_max_retries_blocks_action(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        g._max_retries = 2
        g._active_profile = "RD08_IoT"
        g.run_once()
        g.run_once()
        before = len(be.calls)
        retry_before = g.consecutive_failures
        g.run_once()
        self.assertEqual(len(be.calls), before, "达到 max_retries 后不应再调 nmcli")

    def test_flap_detection_triggers_pause(self):
        """滑动窗口内断连超阈值 -> 标记 flapping。"""
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._flap_threshold = 2
        g._flap_window = 900
        g._dry_run = True
        now = [1000.0]
        g._clock = lambda: now[0]
        for _ in range(3):
            g._flap_events.append(now[0])
        self.assertGreater(len(g._flap_events), g._flap_threshold)

    def test_settle_window_blocks(self):
        """NM 正在 activating 时不插手。"""
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store

        def busy():
            return True

        be.is_busy_activating = busy
        g = Guardian(cfg, be, store, log)
        g._dry_run = False
        g._active_profile = "RD08_IoT"
        g._stop.wait = lambda *a, **k: None  # 不真等
        retry_before = 0
        g._cycle(0, 0)
        self.assertEqual(be.calls, [], "settle 窗口内不应调用 nmcli")

    def test_pick_profile_priority(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._active_profile = "explicit"
        st = be.status()
        self.assertEqual(g._pick_profile(st), "explicit")
        g._active_profile = ""
        g._fallback_profile = "fb"
        self.assertEqual(g._pick_profile(st), "fb")

    def test_apply_config_validates(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g.apply_config({"interval_sec": 30, "max_retries": 10})
        self.assertEqual(g._interval, 30)
        self.assertEqual(g._max_retries, 10)
        with self.assertRaises(ValueError):
            g.apply_config({"interval_sec": 1})  # 低于下限 5

    def test_apply_config_partial_keeps_others(self):
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g.apply_config({"interval_sec": 45})
        c = g.config()
        self.assertEqual(c["interval_sec"], 45)
        self.assertEqual(c["max_retries"], int(cfg["daemon"]["max_retries"]))

    def test_status_shape(self):
        cfg, log, be, store = _mk(scenario="connected", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        s = g.status()
        for k in ("running", "cycles", "last_check_at", "consecutive_failures", "flapping"):
            self.assertIn(k, s)

    def test_lockfile_exclusive(self):
        """flock 独占：第二个实例应拿不到锁并安静退出。仅 POSIX 有 flock。"""
        import sys as _sys

        if os.name != "posix" or _sys.platform.startswith("win"):
            self.skipTest("flock 仅在 POSIX 可用")
        cfg, log, be, store = _mk(scenario="idle", tmpdir=self.tmpdir)
        self.store = store
        lockpath = os.path.join(self.tmpdir, "g.lock")
        g1 = Guardian(cfg, be, store, log)
        g1._lockpath = lockpath
        self.assertTrue(g1._acquire_lock())
        # flock 在**同一进程内**对同一文件的第二次 flock 会成功（锁与 fd 关联），
        # 所以必须用子进程模拟第二个守护实例。
        import subprocess

        code = (
            "import sys; sys.path.insert(0, %r);"
            "from wifimgr.daemon import Guardian;"
            "from wifimgr import config;"
            "from wifimgr.logbus import LogBus;"
            "g = Guardian(config.load(None), None, None, LogBus(use_syslog=False));"
            "g._lockpath = %r;"
            "print('ACQUIRED' if g._acquire_lock() else 'BLOCKED')"
            % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))), lockpath)
        )
        out = subprocess.check_output([sys.executable, "-c", code], text=True)
        self.assertIn("BLOCKED", out, "第二个进程应拿不到锁")
        g1._release_lock()

    def test_start_stop(self):
        cfg, log, be, store = _mk(scenario="connected", tmpdir=self.tmpdir)
        self.store = store
        g = Guardian(cfg, be, store, log)
        g._lockpath = os.path.join(self.tmpdir, "s.lock")
        g._interval = 1
        self.assertTrue(g.start())
        import time as _t

        _t.sleep(0.2)
        self.assertTrue(g.running)
        g.stop()
        self.assertFalse(g.running)


if __name__ == "__main__":
    unittest.main(verbosity=2)
