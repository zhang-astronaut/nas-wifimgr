"""扫描占位记录（phantom）处理测试。

实测发现：NetworkManager 会为「有 profile 但当前扫描不到」的 SSID 吐一行占位记录：

    wlan0:RD08_IoT::0 MHz:0:WPA1 WPA2

BSSID 为空、频率 0 MHz、信号 0。这行**不可连接**（会 ssid-not-found），
展示出来只会让用户点一个连不上的网络。

关键：真正的隐藏网络是 **SSID 为空但 BSSID 存在**，所以按 BSSID 判定是安全的。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import config  # noqa: E402
from wifimgr.backends import fake as fake_mod  # noqa: E402
from wifimgr.terse import parse_terse_lines  # noqa: E402

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


class _StubResult(object):
    def __init__(self, stdout, rc=0, stderr=""):
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


class TestPhantomFiltering(unittest.TestCase):
    """用真实的含占位记录的 nmcli 输出验证。"""

    # 实机抓取：最后一行就是 RD08_IoT 占位记录
    RAW_WITH_PHANTOM = (
        "wlan0:密码是八个八:50\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA2 WPA3\n"
        "wlan0:密码是八个八wifi5:62\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA1 WPA2\n"
        "wlan0::5A\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA2\n"
        "wlan0::D6\\:83\\:04\\:2F\\:3E\\:FD:2412 MHz:47:WPA2\n"
        "wlan0:RD08_IoT::0 MHz:0:WPA1 WPA2\n"
    )

    def _backend(self):
        from wifimgr.backends.nmcli import NMBackend

        fake_mod.set_fixture_dir(FIXTURES)
        cfg = config.load(None)
        log = _Log()
        be = NMBackend(cfg, log, nmcli="/usr/bin/nmcli")
        return be, log

    def test_rows_include_phantom(self):
        """先确认解析层确实看到了占位行（否则后面的过滤测试是空转）。"""
        from wifimgr.backends.nmcli import SCAN_FIELDS

        rows = parse_terse_lines(self.RAW_WITH_PHANTOM, SCAN_FIELDS)
        self.assertEqual(len(rows), 5)
        phantom = [r for r in rows if r["BSSID"] == ""]
        self.assertEqual(len(phantom), 1)
        self.assertEqual(phantom[0]["SSID"], "RD08_IoT")
        self.assertEqual(phantom[0]["FREQ"], "0 MHz")

    def test_scan_filters_phantom(self):
        be, log = self._backend()
        calls = {"n": 0}

        def fake_nm(args, timeout=15, lock=False):
            # 第 1 次是 rescan，第 2 次是主列表，第 3 次是 flags
            calls["n"] += 1
            if calls["n"] == 1:
                return _StubResult("")
            if calls["n"] == 2:
                return _StubResult(self.RAW_WITH_PHANTOM)
            return _StubResult(
                "wlan0:密码是八个八:50\\:4F\\:3B\\:18\\:31\\:9B:100:(none):pair_ccmp group_ccmp psk sae: \n"
            )

        be._nm = fake_nm
        items = be.scan(force=True)
        ssids = [e.ssid for e in items]
        self.assertNotIn("RD08_IoT", ssids, "占位记录应被过滤")
        self.assertEqual(len(items), 4, "应保留 4 个可见网络")
        # 隐藏网络（SSID 空但 BSSID 在）必须保留
        self.assertIn("", ssids, "隐藏网络不应被误伤")
        # 应记了一条事件
        self.assertTrue(any("phantom" in r[2] for r in log.records))

    def test_hidden_network_kept(self):
        """SSID 为空但 BSSID 存在 = 隐藏网络，必须保留。"""
        be, _ = self._backend()
        calls = {"n": 0}

        def fake_nm(args, timeout=15, lock=False):
            calls["n"] += 1
            if calls["n"] == 1:
                return _StubResult("")
            if calls["n"] == 2:
                return _StubResult(self.RAW_WITH_PHANTOM)
            return _StubResult("")

        be._nm = fake_nm
        items = be.scan(force=True)
        hidden = [e for e in items if e.hidden]
        self.assertTrue(hidden, "隐藏网络应保留")
        for h in hidden:
            self.assertTrue(h.bssid, "隐藏网络必须有 BSSID")

    def test_p2p0_rows_filtered(self):
        """p2p0 的行必须被丢弃（否则结果翻倍）。"""
        be, _ = self._backend()
        calls = {"n": 0}
        raw = (
            "p2p0:密码是八个八:50\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA2 WPA3\n"
            + self.RAW_WITH_PHANTOM
        )

        def fake_nm(args, timeout=15, lock=False):
            calls["n"] += 1
            if calls["n"] == 1:
                return _StubResult("")
            if calls["n"] == 2:
                return _StubResult(raw)
            return _StubResult("")

        be._nm = fake_nm
        items = be.scan(force=True)
        for e in items:
            self.assertEqual(e.iface, "wlan0")
        self.assertEqual(len(items), 4, "p2p0 的 1 行应被丢弃")


if __name__ == "__main__":
    unittest.main(verbosity=2)
