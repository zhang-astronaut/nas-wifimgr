"""CLI 与应用组装测试。

重点：``cmd_serve`` 的组装路径曾经因为 ``Ctx(daemon=...)`` 拼错参数而崩溃，
而这个错误只在真正启动服务时才暴露 —— 单测覆盖不到。所以这里显式构造
与 serve 相同的对象，确保参数名对得上。
"""

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import __main__ as cli  # noqa: E402
from wifimgr import config  # noqa: E402
from wifimgr.api import Ctx, ScanCache  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.daemon import Guardian  # noqa: E402
from wifimgr.store import Store  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class _Log(object):
    def __getattr__(self, name):
        return lambda *a, **k: None


class TestCtxAssembly(unittest.TestCase):
    """复现 serve() 的组装步骤。"""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        fake_mod.set_fixture_dir(FIXTURES)

    def tearDown(self):
        if getattr(self, "store", None):
            self.store.close_all()
        self._t.cleanup()

    def test_ctx_accepts_guardian_kwarg(self):
        """Ctx 的关键字参数必须是 guardian（曾误写成 daemon 导致启动崩溃）。"""
        cfg = config.load(None)
        log = _Log()
        be = fake_mod.FakeBackend(cfg, log)
        self.store = Store(os.path.join(self._t.name, "t.db"))
        be.set_store(self.store)
        g = Guardian(cfg, be, self.store, log)
        ctx = Ctx(cfg, be, self.store, log, guardian=g, scanner=ScanCache())
        self.assertIs(ctx.guardian, g)
        self.assertIsNotNone(ctx.scanner)
        self.assertIsNotNone(ctx.version)

    def test_ctx_signature_matches_daemon_kwarg_absence(self):
        """显式确认 daemon= 不是合法参数（防止回归）。"""
        cfg = config.load(None)
        log = _Log()
        be = fake_mod.FakeBackend(cfg, log)
        self.store = Store(os.path.join(self._t.name, "t.db"))
        with self.assertRaises(TypeError):
            Ctx(cfg, be, self.store, log, daemon=None, scanner=ScanCache())


class TestParser(unittest.TestCase):
    def test_all_subcommands_registered(self):
        p = cli.build_parser()
        found = set()
        for action in p._subparsers._group_actions:
            found.update(action.choices.keys())
        for name in (
            "serve",
            "scan",
            "status",
            "connect",
            "profiles",
            "doctor",
            "selftest",
            "probe-sae",
        ):
            self.assertIn(name, found, "缺少子命令 %s" % name)

    def test_no_subcommand_prints_help(self):
        self.assertEqual(cli.main([]), 1)

    def test_scan_json(self):
        fake_mod.set_fixture_dir(FIXTURES)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = cli.main(["--backend", "fake", "--no-syslog", "scan", "--json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertIn('"ok"', buf.getvalue())

    def test_doctor_json(self):
        fake_mod.set_fixture_dir(FIXTURES)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = cli.main(["--backend", "fake", "--no-syslog", "doctor", "--json"])
        finally:
            sys.stdout = old
        self.assertIn(rc, (0, 1))
        self.assertIn("checks", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
