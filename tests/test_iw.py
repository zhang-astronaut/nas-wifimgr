"""iw link 解析测试（含真实抓取的输出样本）。

实测（NAS 192.168.31.47 / rtl8188fu）::

    Connected to 62:4f:3b:18:31:9b (on wlan0)
    \tSSID: \\xe5\\xaf\\x86\\xe7\\xa0\\x81\\xe6\\x98\\xaf\\xe5\\x85\\xab\\xe4\\xb8\\xaa\\xe5\\x85\\xabwifi5
    \tfreq: 2412
    \tsignal: -17 dBm
    \ttx bitrate: 150.0 MBit/s
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr.backends.base import decode_iw_ssid, parse_iw_link  # noqa: E402

# 实机抓取的原始行（注意行首是制表符）
REAL_LINK = (
    "Connected to 62:4f:3b:18:31:9b (on wlan0)\n"
    "\tSSID: \\xe5\\xaf\\x86\\xe7\\xa0\\x81\\xe6\\x98\\xaf\\xe5\\x85\\xab"
    "\\xe4\\xb8\\xaa\\xe5\\x85\\xabwifi5\n"
    "\tfreq: 2412\n"
    "\tsignal: -17 dBm\n"
    "\ttx bitrate: 150.0 MBit/s\n"
)

EXPECTED_SSID = "密码是八个八wifi5"


class TestDecodeIwSsid(unittest.TestCase):
    def test_real_chinese_ssid(self):
        """实机样本：iw 用 \\xNN 转义输出中文 SSID。"""
        got = decode_iw_ssid(
            "\\xe5\\xaf\\x86\\xe7\\xa0\\x81\\xe6\\x98\\xaf\\xe5\\x85\\xab"
            "\\xe4\\xb8\\xaa\\xe5\\x85\\xabwifi5"
        )
        self.assertEqual(got, EXPECTED_SSID, "解码结果不对：%r" % got)

    def test_ascii_passthrough(self):
        self.assertEqual(decode_iw_ssid("MyPlainSSID"), "MyPlainSSID")

    def test_empty(self):
        self.assertEqual(decode_iw_ssid(""), "")

    def test_mixed_escaped_and_literal(self):
        """转义段 + ASCII 尾巴（实机样本就是这个形态）。"""
        self.assertEqual(
            decode_iw_ssid("\\xe5\\xaf\\x86wifi5"), "密wifi5"
        )

    def test_uppercase_x(self):
        """\\XNN 大写形式也要认。"""
        self.assertEqual(decode_iw_ssid("\\X41\\X42"), "AB")

    def test_pure_ascii_escape(self):
        self.assertEqual(decode_iw_ssid("\\x41\\x42\\x43"), "ABC")

    def test_empty_escape_brackets(self):
        """SSID 为空（隐藏网络）时 iw 输出空串，不能崩。"""
        self.assertEqual(decode_iw_ssid(""), "")

    def test_malformed_does_not_crash(self):
        self.assertIsInstance(decode_iw_ssid("\\xZZ\\x41"), str)


class TestParseIwLink(unittest.TestCase):
    def test_real_output(self):
        got = parse_iw_link(REAL_LINK)
        self.assertTrue(got["connected"])
        self.assertEqual(got["bssid"], "62:4F:3B:18:31:9B")
        self.assertEqual(got["ssid"], EXPECTED_SSID)
        self.assertEqual(got["freq"], 2412)
        self.assertEqual(got["signal"], -17)

    def test_not_connected(self):
        got = parse_iw_link("Not connected.\n")
        self.assertFalse(got["connected"])
        self.assertEqual(got["ssid"], "")
        self.assertIsNone(got["signal"])

    def test_empty(self):
        got = parse_iw_link("")
        self.assertFalse(got["connected"])

    def test_ascii_ssid(self):
        text = (
            "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n"
            "\tSSID: HomeNet\n"
            "\tfreq: 2437\n"
            "\tsignal: -42 dBm\n"
        )
        got = parse_iw_link(text)
        self.assertEqual(got["ssid"], "HomeNet")
        self.assertEqual(got["signal"], -42)

    def test_no_ssid_line(self):
        text = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tsignal: -50 dBm\n"
        got = parse_iw_link(text)
        self.assertTrue(got["connected"])
        self.assertEqual(got["ssid"], "")
        self.assertEqual(got["signal"], -50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
