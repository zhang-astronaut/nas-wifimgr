"""keyfile 渲染 / 转义 / 安全不变量测试。

重点覆盖三个实测坑：
  D1 nmcli connection load 假成功 → 所以必须有回读校验（这里测渲染侧的完整性）
  D2 type 必须是 wifi
  D3 bssid 必须是分号十进制
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifimgr import nmkey  # noqa: E402
from wifimgr.errors import ValidationError  # noqa: E402


class TestEscaping(unittest.TestCase):
    def test_special_chars(self):
        self.assertEqual(nmkey.esc("a:b"), "a\\:b")
        self.assertEqual(nmkey.esc("a;b"), "a\\;b")
        self.assertEqual(nmkey.esc("a#b"), "a\\#b")
        self.assertEqual(nmkey.esc("a\\b"), "a\\\\b")
        self.assertEqual(nmkey.esc("a b"), "a\\sb")
        self.assertEqual(nmkey.esc("a=b"), "a\\=b")
        self.assertEqual(nmkey.esc("a[b]"), "a\\[b\\]")

    def test_utf8_preserved(self):
        """中文 SSID 必须原样保留（GLib keyfile 天然 UTF-8 安全）。"""
        self.assertEqual(nmkey.esc("密码是八个八"), "密码是八个八")

    def test_roundtrip(self):
        # 不含制表符的输入往返一致（GLib 用 \s 统一表示空白，制表符不可还原）
        for raw in ("p@ss w#rd;[]=x\\y", "密码是八个八", "a\\b", "new\nline", "a=b"):
            self.assertEqual(nmkey.unesc(nmkey.esc(raw)), raw)

    def test_tab_is_lossy_by_design(self):
        """制表符与空格都映射为 \\s，往返不可还原 —— 这是 GLib keyfile 的限制。"""
        self.assertEqual(nmkey.esc("a\tb"), "a\\sb")
        self.assertEqual(nmkey.esc("a b"), "a\\sb")


class TestValidatePsk(unittest.TestCase):
    def test_valid_8_char(self):
        self.assertEqual(nmkey.validate_psk("testpass1"), "passphrase")

    def test_valid_64_hex(self):
        self.assertEqual(nmkey.validate_psk("a" * 64), "hex")

    def test_too_short(self):
        with self.assertRaises(ValidationError):
            nmkey.validate_psk("1234567")

    def test_too_long(self):
        with self.assertRaises(ValidationError):
            nmkey.validate_psk("a" * 64 + "b")

    def test_multibyte_length_by_bytes(self):
        """长度按 UTF-8 字节算，不是字符数。"""
        nmkey.validate_psk("中" * 3)  # 3 字符 = 9 字节，合法
        with self.assertRaises(ValidationError):
            nmkey.validate_psk("中" * 2)  # 2 字符 = 6 字节，太短
        with self.assertRaises(ValidationError):
            nmkey.validate_psk("中" * 22)  # 66 字节，太长

    def test_none_rejected(self):
        with self.assertRaises(ValidationError):
            nmkey.validate_psk(None)


class TestRenderKeyfile(unittest.TestCase):
    def test_wpa_psk_basic(self):
        body = nmkey.render_keyfile(
            profile_name="test-net", ssid="MyNet", password="testpass1", key_mgmt="wpa-psk"
        )
        self.assertIn("id=test-net", body)
        self.assertIn("type=wifi", body)
        self.assertIn("ssid=MyNet", body)
        self.assertIn("key-mgmt=wpa-psk", body)
        self.assertIn("psk=testpass1", body)
        self.assertIn("interface-name=wlan0", body)

    def test_type_must_be_wifi_not_802_11(self):
        """D2: type 写成 802-11-wireless 会导致 NM plugin 不认。"""
        body = nmkey.render_keyfile(profile_name="x", ssid="y", password="12345678")
        self.assertIn("type=wifi", body)
        self.assertNotIn("type=802-11-wireless", body)

    def test_bssid_uses_semicolon_decimals(self):
        """D3: bssid 必须是分号十进制，不是转义冒号。"""
        body = nmkey.render_keyfile(
            profile_name="x",
            ssid="y",
            password="12345678",
            bssid="50:4F:3B:18:31:9B",
        )
        self.assertIn("bssid=80;79;59;24;49;155;", body)
        self.assertNotIn("bssid=50\\:", body)

    def test_sae_key_mgmt(self):
        body = nmkey.render_keyfile(
            profile_name="x", ssid="y", password="12345678", key_mgmt="sae"
        )
        self.assertIn("key-mgmt=sae", body)
        # SAE 的密码字段在 NM keyfile 里就叫 psk，不是 sae_password
        self.assertIn("psk=12345678", body)
        self.assertNotIn("sae_password", body)

    def test_open_network_no_password(self):
        body = nmkey.render_keyfile(profile_name="x", ssid="y", key_mgmt="none")
        self.assertIn("key-mgmt=none", body)
        self.assertNotIn("psk=", body)

    def test_hidden_network(self):
        body = nmkey.render_keyfile(
            profile_name="x", ssid="HiddenNet", password="12345678", hidden=True
        )
        self.assertIn("hidden=yes", body)

    def test_chinese_ssid(self):
        body = nmkey.render_keyfile(
            profile_name="密码是八个八", ssid="密码是八个八", password="testpass1"
        )
        self.assertIn("ssid=密码是八个八", body)
        self.assertIn("id=密码是八个八", body)

    def test_stable_uuid(self):
        a = nmkey.stable_uuid("my-net")
        b = nmkey.stable_uuid("my-net")
        self.assertEqual(a, b)
        self.assertNotEqual(a, nmkey.stable_uuid("other-net"))
        self.assertEqual(len(a), 36)

    def test_extra_whitelist_enforced(self):
        with self.assertRaises(ValidationError):
            nmkey.render_keyfile(
                profile_name="x",
                ssid="y",
                password="12345678",
                extra={"evil": "1"},
            )

    def test_extra_allowed_key(self):
        body = nmkey.render_keyfile(
            profile_name="x", ssid="y", password="12345678", extra={"pmf": "1"}
        )
        self.assertIn("pmf=1", body)

    def test_invalid_key_mgmt(self):
        with self.assertRaises(ValidationError):
            nmkey.render_keyfile(profile_name="x", ssid="y", password="12345678", key_mgmt="wpa-eap")

    def test_ssid_newline_rejected(self):
        with self.assertRaises(ValidationError):
            nmkey.render_keyfile(profile_name="x", ssid="a\nb", password="12345678")

    def test_ssid_too_long(self):
        with self.assertRaises(ValidationError):
            nmkey.render_keyfile(profile_name="x", ssid="a" * 33, password="12345678")


class TestKeyfilePath(unittest.TestCase):
    def test_normal(self):
        p = nmkey.keyfile_path("/etc/NetworkManager/system-connections", "MyNet")
        self.assertTrue(p.endswith("MyNet.nmconnection"))

    def test_chinese_ok(self):
        p = nmkey.keyfile_path("/k", "密码是八个八")
        self.assertTrue(p.endswith("密码是八个八.nmconnection"))

    def test_path_traversal_rejected(self):
        """profile_name 里的 / 会写到目录外，必须拒绝而不是静默过滤。"""
        for bad in ("../evil", "a/b", "..", "a\\b", "/abs", "a\tb", "a;b", "a#b"):
            with self.assertRaises(ValidationError):
                nmkey.keyfile_path("/etc/NetworkManager/system-connections", bad)

    def test_empty_rejected(self):
        with self.assertRaises(ValidationError):
            nmkey.keyfile_path("/k", "")

    def test_leading_space_rejected(self):
        with self.assertRaises(ValidationError):
            nmkey.keyfile_path("/k", " net")


class TestWriteKeyfile(unittest.TestCase):
    def test_permissions_are_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.nmconnection")
            body = nmkey.render_keyfile(profile_name="t", ssid="s", password="12345678")
            nmkey.write_keyfile(path, body)
            if os.name == "posix":
                # Windows 的 os.chmod 只映射只读位，无法表达 0600
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(mode, 0o600, "keyfile 必须是 0600")
            self.assertTrue(os.path.isfile(path))

    def test_no_temp_left_behind(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.nmconnection")
            nmkey.write_keyfile(
                path, nmkey.render_keyfile(profile_name="t", ssid="s", password="12345678")
            )
            leftovers = [f for f in os.listdir(d) if "wifimgr-tmp" in f]
            self.assertEqual(leftovers, [], "不应残留临时文件")


class TestShredAndSnapshot(unittest.TestCase):
    def test_shred_removes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w") as fh:
                fh.write("secret")
            self.assertTrue(nmkey.shred_file(p))
            self.assertFalse(os.path.exists(p))

    def test_snapshot_created(self):
        with tempfile.TemporaryDirectory() as d:
            keys = os.path.join(d, "keys")
            snaps = os.path.join(d, "snaps")
            os.makedirs(keys)
            with open(os.path.join(keys, "net.nmconnection"), "w") as fh:
                fh.write("[connection]\n")
            out = nmkey.snapshot_existing(keys, "net", snaps, keep=5)
            self.assertIsNotNone(out)
            self.assertTrue(os.path.exists(out))
            if os.name == "posix":
                self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)

    def test_snapshot_skipped_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            keys = os.path.join(d, "keys")
            os.makedirs(keys)
            self.assertIsNone(nmkey.snapshot_existing(keys, "nope", os.path.join(d, "s")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
