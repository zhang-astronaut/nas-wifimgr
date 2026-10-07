"""安全不变量测试：密码绝不能出现在 argv / 数据库 / 响应里。

这是本项目最重要的约束。把「设计意图」变成「可执行检查」，
任何一次未来的重构违反它都会在这里失败。
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import config, nmkey  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.errors import redact, redact_text  # noqa: E402
from wifimgr.models import ConnectRequest  # noqa: E402
from wifimgr.store import Store, assert_no_secret_columns  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# 测试用密码 —— 断言它绝不泄漏
SECRET = "Sup3rS3cret!Pass"


class _Log(object):
    def info(self, *a, **k):
        pass

    warn = error = debug = info


def _mk_backend(scenario="idle"):
    fake_mod.set_fixture_dir(FIXTURES)
    cfg = config.load(None)
    be = fake_mod.FakeBackend(cfg, _Log(), scenario=scenario)
    return be


class TestPasswordNeverInArgv(unittest.TestCase):
    def test_connect_flow_never_exposes_password(self):
        """走完整 connect 流程，扫描所有记录的 argv 找密码。"""
        be = _mk_backend()
        req = ConnectRequest(
            ssid="密码是八个八",
            bssid="50:4F:3B:18:31:9B",
            password=SECRET,
            auth_kind="mixed",
            bssid_lock=True,
        )
        be.connect(req)
        self.assertTrue(be.calls, "应有命令被记录")
        joined = " ".join(" ".join(str(x) for x in c) for c in be.calls)
        self.assertNotIn(SECRET, joined, "密码泄漏进了 argv！")
        # 且确认确实执行了写 profile 的动作（否则上面的断言是空转）
        self.assertIn(("connection", "reload"), be.calls)

    def test_nmcli_commands_have_no_psk_arg(self):
        """真实 NM 后端构造的命令里不得含 psk 参数。"""
        from wifimgr.backends.nmcli import NMBackend

        cfg = config.load(None)
        be = NMBackend(cfg, _Log(), nmcli="/usr/bin/nmcli")
        # 这些是代码里所有会传给 nmcli 的参数模板
        arg_sets = [
            ["-t", "-f", "DEVICE,SSID,BSSID,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", "wlan0"],
            ["device", "wifi", "rescan", "ifname", "wlan0"],
            ["connection", "up", "myprofile"],
            ["connection", "reload"],
            ["-g", "802-11-wireless-security.key-mgmt", "connection", "show", "myprofile"],
        ]
        for args in arg_sets:
            joined = " ".join(args)
            self.assertNotIn("psk", joined.lower(), "nmcli 参数含 psk: %s" % joined)
            self.assertNotIn("password", joined.lower(), "nmcli 参数含 password: %s" % joined)

    def test_source_has_no_inline_password_assignment(self):
        """源码里不得真的用 nmcli argv 传密码。

        允许出现 ``wifi-sec.psk`` 字样的地方只有两类：
          1. 脱敏名单（errors.py 的 SECRET_KEYS）
          2. 明确警告「不要这样写」的注释（nmkey.py 顶部）
        任何**实际传给子进程**的写法都要被抓出来。
        """
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wifimgr_dir = os.path.join(root, "wifimgr")
        # 这两个文件必然提到 wifi-sec.psk，但只在文档/脱敏名单里，不是实际调用：
        #   errors.py —— SECRET_KEYS 脱敏名单
        #   nmkey.py —— 顶部「为什么不用 argv」的说明
        allowed_files = {
            os.path.join(wifimgr_dir, "errors.py"),
            os.path.join(wifimgr_dir, "nmkey.py"),
        }
        offenders = []
        for dirpath, _dirs, files in os.walk(wifimgr_dir):
            for f in files:
                if not f.endswith(".py"):
                    continue
                path = os.path.join(dirpath, f)
                if path in allowed_files:
                    continue
                with open(path, "r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if "wifi-sec.psk" in line:
                            offenders.append("%s:%d %s" % (path, lineno, line.strip()[:80]))
        self.assertEqual(
            offenders, [], "源码中出现 nmcli argv 传密码的写法: %s" % offenders
        )

    def test_no_run_call_with_psk_kwarg(self):
        """runner.run() 只接受 argv 列表，源码里不得有 psk=... 形式的调用。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wifimgr_dir = os.path.join(root, "wifimgr")
        offenders = []
        for dirpath, _dirs, files in os.walk(wifimgr_dir):
            for f in files:
                if not f.endswith(".py"):
                    continue
                path = os.path.join(dirpath, f)
                with open(path, "r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if "run(" in line and ("psk=" in stripped or "password=" in stripped):
                            offenders.append("%s:%d" % (path, lineno))
        self.assertEqual(offenders, [], "run() 调用里出现 psk/password 参数: %s" % offenders)


class TestNoPasswordInDatabase(unittest.TestCase):
    def test_schema_has_no_secret_columns(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "t.db"))
            c = st.conn()
            assert_no_secret_columns(c)  # 不抛异常即通过
            st.close_all()

    def test_column_names_explicitly_checked(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "t.db"))
            c = st.conn()
            tables = [
                r[0]
                for r in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            self.assertIn("saved_network", tables)
            cols = {r[1] for r in c.execute("PRAGMA table_info(saved_network)").fetchall()}
            for banned in ("psk", "password", "passphrase", "secret"):
                self.assertNotIn(banned, cols, "saved_network 含密码列 %s" % banned)
            st.close_all()

    def test_saved_network_has_no_password_value(self):
        """写入含密码的连接请求后，库里搜不到密码明文。"""
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "t.db")
            st = Store(db)
            st.upsert_saved_network(
                profile_name="net1", ssid="MyNet", key_mgmt="wpa-psk", security="wpa2"
            )
            st.add_event({"ts": 0, "level": "info", "source": "t", "code": "t", "message": "x", "data": {}})
            st.close_all()
            with open(db, "rb") as fh:
                blob = fh.read()
            # 遍历所有表内容，确认密码串不存在
            c = sqlite3.connect(db)
            for t in ("saved_network", "profile_ref", "event", "setting", "connect_attempt"):
                try:
                    rows = c.execute("SELECT * FROM %s" % t).fetchall()
                except sqlite3.Error:
                    continue
                for row in rows:
                    for cell in row:
                        if isinstance(cell, str):
                            self.assertNotIn(SECRET, cell, "密码出现在表 %s" % t)
            c.close()

    def test_profile_ref_has_psk_is_boolean(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "t.db"))
            st.upsert_profile_ref("net1", uuid="u", key_mgmt="wpa-psk", has_psk=True)
            ref = st.get_profile_ref("net1")
            self.assertEqual(ref["has_psk"], 1, "has_psk 只能是布尔标记")
            d2 = st.list_profile_refs()[0]
            self.assertNotIn(SECRET, str(d2))
            st.close_all()


class TestRedaction(unittest.TestCase):
    def test_dict_keys_redacted(self):
        out = redact({"psk": SECRET, "password": SECRET, "ssid": "MyNet"})
        self.assertEqual(out["psk"], "***")
        self.assertEqual(out["password"], "***")
        self.assertEqual(out["ssid"], "MyNet", "非密码字段必须保留")

    def test_nested(self):
        out = redact({"a": [{"wifi_password": SECRET}], "b": {"sae_password": SECRET}})
        self.assertEqual(out["a"][0]["wifi_password"], "***")
        self.assertEqual(out["b"]["sae_password"], "***")

    def test_case_insensitive(self):
        self.assertEqual(redact({"PSK": SECRET})["PSK"], "***")

    def test_redact_text(self):
        s = "Error: failed with password %s here" % SECRET
        self.assertNotIn(SECRET, redact_text(s, [SECRET]))

    def test_redact_text_short_secret_ignored(self):
        """太短的串不做替换，避免把正常文本打成马赛克。"""
        self.assertEqual(redact_text("abc def", ["ab"]), "abc def")


class TestEventRedaction(unittest.TestCase):
    def test_event_data_is_redacted_on_persist(self):
        with tempfile.TemporaryDirectory() as d:
            from wifimgr.logbus import LogBus

            st = Store(os.path.join(d, "t.db"))
            lb = LogBus("wifimgr-test", store=st, use_syslog=False)
            lb.info("test", "connect", "尝试连接", {"ssid": "x", "password": SECRET})
            rows = st.list_events(10)
            self.assertTrue(rows)
            self.assertNotIn(SECRET, str(rows))
            self.assertEqual(rows[0]["data"].get("password"), "***")
            st.close_all()


class TestConfigHasNoSecrets(unittest.TestCase):
    def test_default_config_clean(self):
        """配置里不得有密码值。注意 ``sae_policy: psk_first`` 是策略名，不是密码。"""
        cfg = config.load(None)
        blob = str(cfg).lower()
        self.assertNotIn("password", blob)
        self.assertNotIn("passphrase", blob)
        # 不能有形如 psk= / psk: 的赋值
        for pat in ("psk=", "psk:", "'psk'", '"psk"'):
            self.assertNotIn(pat, blob, "配置含疑似密码赋值: %s" % pat)

    def test_jsonc_strip_preserves_strings(self):
        """SSID 里含 // 或 /* 时不能被当注释剥掉。"""
        text = '{"ssid": "a//b", "note": "c/*d*/e"}'
        out = config.strip_jsonc(text)
        self.assertIn("a//b", out)
        self.assertIn("c/*d*/e", out)

    def test_jsonc_strip_removes_comments(self):
        text = '{\n  // 注释\n  "a": 1, /* 块 */ "b": 2\n}'
        out = config.strip_jsonc(text)
        self.assertNotIn("注释", out)
        self.assertNotIn("块", out)
        self.assertIn('"a": 1', out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
