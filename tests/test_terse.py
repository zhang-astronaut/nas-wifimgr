"""terse / dev show / BSSID 编码的单元测试。

全部基于 NAS 实测抓取的真实输出，包含中文 SSID、空 SSID 隐藏网络、
转义 BSSID、缺失字段等真实边界。
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr.terse import (  # noqa: E402
    bssid_to_nm_bytes,
    nm_bytes_to_bssid,
    normalize_bssid,
    parse_dev_show,
    parse_terse,
    parse_terse_lines,
    unescape_dev_show_value,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def read_fixture(name):
    with io.open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return fh.read()


class TestParseTerse(unittest.TestCase):
    def test_real_mixed_line(self):
        """实机样本：中文 SSID + 转义 BSSID + 混合加密。"""
        line = "wlan0:密码是八个八:50\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA2 WPA3"
        row = parse_terse(
            line, ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"]
        )
        self.assertEqual(row["DEVICE"], "wlan0")
        self.assertEqual(row["SSID"], "密码是八个八")
        self.assertEqual(row["BSSID"], "50:4F:3B:18:31:9B")
        self.assertEqual(row["FREQ"], "2412 MHz")
        self.assertEqual(row["SIGNAL"], "100")
        self.assertEqual(row["SECURITY"], "WPA2 WPA3")

    def test_empty_ssid_hidden_network(self):
        """隐藏 AP：SSID 为空，BSSID 仍要正确还原。"""
        line = "wlan0::5A\\:4F\\:3B\\:18\\:31\\:9B:2412 MHz:100:WPA2"
        row = parse_terse(
            line, ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"]
        )
        self.assertEqual(row["SSID"], "")
        self.assertEqual(row["BSSID"], "5A:4F:3B:18:31:9B")

    def test_trailing_empty_field(self):
        """实机样本末尾 IN-USE 为空（未连接时）。"""
        line = "wlan0::B2\\:39\\:B3\\:E4\\:18\\:8B:2412 MHz:30:"
        row = parse_terse(
            line, ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "IN-USE"]
        )
        self.assertEqual(row["SSID"], "")
        self.assertEqual(row["SIGNAL"], "30")
        self.assertEqual(row["IN-USE"], "")

    def test_missing_fields_padded(self):
        """字段数少于声明时补空串，不抛异常。

        实机样本里就有这种行：CMCC-39qu 那行 SECURITY 为空。
        """
        row = parse_terse(
            "wlan0:CMCC-39qu:9C\\:FE\\:A1\\:6F\\:F6\\:27:2472 MHz:39",
            ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"],
        )
        self.assertEqual(row["SIGNAL"], "39")
        self.assertEqual(row["SECURITY"], "")
        # 只给 3 个字段、声明 5 个：后两个补空
        row2 = parse_terse("wlan0:x:AA", ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL"])
        self.assertEqual(row2["BSSID"], "AA")
        self.assertEqual(row2["FREQ"], "")
        self.assertEqual(row2["SIGNAL"], "")

    def test_backslash_before_separator(self):
        """``\\\\:``（反斜杠 + 分隔符）必须被当成两个字段，不能误还原。"""
        # 语义：SSID = 反斜杠, 然后是分隔符, 然后 BSSID
        row = parse_terse("wlan0:a\\\\b:AA", ["DEVICE", "SSID", "BSSID"])
        self.assertEqual(row["SSID"], "a\\b")
        self.assertEqual(row["BSSID"], "AA")

    def test_escaped_colon_in_ssid(self):
        """SSID 内含字面冒号。"""
        row = parse_terse("wlan0:My\\:Net:AA", ["DEVICE", "SSID", "BSSID"])
        self.assertEqual(row["SSID"], "My:Net")
        self.assertEqual(row["BSSID"], "AA")

    def test_empty_input(self):
        row = parse_terse("", ["A", "B"])
        self.assertEqual(row, {"A": "", "B": ""})
        row = parse_terse(None, ["A", "B"])
        self.assertEqual(row, {"A": "", "B": ""})

    def test_real_fixture_all_rows(self):
        """跑完整真实扫描样本，逐行断言关键字段。"""
        text = read_fixture("scan_wlan0.txt")
        fields = ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"]
        rows = parse_terse_lines(text, fields)
        self.assertEqual(len(rows), 11, "wlan0 扫描应为 11 个网络")
        for r in rows:
            self.assertEqual(r["DEVICE"], "wlan0")
            self.assertRegex(r["BSSID"], r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
        ssids = [r["SSID"] for r in rows]
        self.assertIn("密码是八个八", ssids)
        self.assertIn("密码是八个八wifi5", ssids)
        self.assertIn("CMCC-5088", ssids)
        self.assertIn("福福的Wi-Fi", ssids)
        self.assertIn("", ssids, "样本中应含隐藏网络（空 SSID）")
        mixed = [r for r in rows if r["SECURITY"] == "WPA2 WPA3"]
        self.assertTrue(mixed, "应含 WPA2/WPA3 混合网络")

    def test_rich_fixture_flags(self):
        text = read_fixture("scan_rich.txt")
        fields = ["DEVICE", "SSID", "BSSID", "SIGNAL", "WPA-FLAGS", "RSN-FLAGS", "IN-USE"]
        rows = parse_terse_lines(text, fields)
        self.assertEqual(len(rows), 11)
        sae_rows = [r for r in rows if "sae" in r["RSN-FLAGS"].split()]
        self.assertTrue(sae_rows, "应含声明支持 sae 的 AP")
        for r in sae_rows:
            self.assertIn("psk", r["RSN-FLAGS"].split(), "混合 AP 应同时含 psk")
        tkip = [r for r in rows if "tkip" in r["WPA-FLAGS"]]
        self.assertTrue(tkip, "应含 WPA1/TKIP 网络")


class TestParseDevShow(unittest.TestCase):
    """D5: dev show 必须用 -f（不加 -t），输出是定宽 KEY: value。"""

    def test_real_connected_output(self):
        text = (
            "GENERAL.STATE:                          100 (connected)\n"
            "GENERAL.CONNECTION:                     密码是八个八wifi5\n"
            "IP4.ADDRESS[1]:                         192.168.31.64/24\n"
        )
        out = parse_dev_show(text)
        self.assertEqual(out["GENERAL.STATE"], "100 (connected)")
        self.assertEqual(out["GENERAL.CONNECTION"], "密码是八个八wifi5")
        self.assertEqual(out["IP4.ADDRESS"], ["192.168.31.64/24"])
        self.assertEqual(out["IP4.ADDRESS_first"], "192.168.31.64/24")

    def test_disconnected(self):
        text = "GENERAL.STATE:                          30 (disconnected)\n"
        out = parse_dev_show(text)
        self.assertEqual(out["GENERAL.STATE"], "30 (disconnected)")

    def test_multiple_addresses(self):
        text = (
            "IP4.ADDRESS[1]:                         192.168.31.64/24\n"
            "IP4.ADDRESS[2]:                         192.168.31.65/24\n"
        )
        out = parse_dev_show(text)
        self.assertEqual(len(out["IP4.ADDRESS"]), 2)
        self.assertEqual(out["IP4.ADDRESS"][1], "192.168.31.65/24")

    def test_garbage_lines_ignored(self):
        out = parse_dev_show("Error: something\n\nnot a valid line here\n")
        self.assertEqual(out, {})


class TestBssidEncoding(unittest.TestCase):
    """D3: keyfile 里 bssid 是分号十进制字节。"""

    def test_encode(self):
        self.assertEqual(bssid_to_nm_bytes("50:4F:3B:18:31:9B"), "80;79;59;24;49;155;")

    def test_encode_lowercase(self):
        self.assertEqual(bssid_to_nm_bytes("50:4f:3b:18:31:9b"), "80;79;59;24;49;155;")

    def test_roundtrip(self):
        for b in ("50:4F:3B:18:31:9B", "62:4F:3B:18:31:9B", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            self.assertEqual(nm_bytes_to_bssid(bssid_to_nm_bytes(b)), b)

    def test_real_ap_bssid(self):
        """实机主路由 BSSID。"""
        self.assertEqual(bssid_to_nm_bytes("50:4F:3B:18:31:9B"), "80;79;59;24;49;155;")
        self.assertEqual(bssid_to_nm_bytes("62:4F:3B:18:31:9B"), "98;79;59;24;49;155;")

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            bssid_to_nm_bytes("50:4F:3B:18:31")
        with self.assertRaises(ValueError):
            bssid_to_nm_bytes("ZZ:4F:3B:18:31:9B")

    def test_normalize_variants(self):
        self.assertEqual(normalize_bssid("50:4f:3b:18:31:9b"), "50:4F:3B:18:31:9B")
        self.assertEqual(normalize_bssid("80;79;59;24;49;155;"), "50:4F:3B:18:31:9B")
        self.assertEqual(normalize_bssid(""), "")
        self.assertEqual(normalize_bssid("garbage"), "")

    def test_unescape_dev_show(self):
        """nmcli 有时把 bssid 输出成 50\\:4F\\:... 形式。"""
        self.assertEqual(unescape_dev_show_value("50\\:4F\\:3B\\:18\\:31\\:9B"), "50:4F:3B:18:31:9B")
        self.assertEqual(unescape_dev_show_value("plain"), "plain")


if __name__ == "__main__":
    unittest.main(verbosity=2)
