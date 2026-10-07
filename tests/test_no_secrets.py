"""源码级安全审计：禁止把真实口令写进代码。

起因：准备把代码推到公开仓库时扫描发现，
``backends/nmcli.py`` 的 SAE 探测把**真实 WiFi 密码**硬编码成了默认值
（当时是我实测该机器用的真实口令）。这类东西一旦 push 到公开仓库
就等于永久泄漏，而且以后每次提交都要靠人肉 grep 去找。

这里把它变成可执行断言：源码里不得出现形如
``password="8+位数字串"`` 的字面量（测试数据必须用显式的占位常量）。
"""

import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "wifimgr")

# 明确允许出现的「测试用」占位口令。改动这里等于主动声明「这是假密码」。
ALLOWED_LITERALS = {
    "testpass1",
    "12345678",          # WPA 最小长度，官方文档示例
    "password123",
    "Sup3rS3cret!Pass",  # test_security.py 专用
    "wifimgr-probe-placeholder",  # SAE 能力探测的占位口令（nmcli.py）
}

# 匹配 password= / psk= / passwd= 后跟的非占位字符串字面量
_LITERAL_RE = re.compile(
    r"""(?:password|passwd|psk|passphrase|sae_password)\s*=\s*(["'])([^"']{1,128})\1""",
    re.I,
)

# 允许出现字面量的文件（测试里构造样本是合理的）
_ALLOW_FILES = re.compile(r"tests?[/\\]test_|_test\.py$")


def _py_files():
    for dirpath, dirnames, filenames in os.walk(SRC):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in filenames:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)


def _read(path):
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


class TestNoHardcodedPasswords(unittest.TestCase):
    """源码不得含真实口令字面量。"""

    def test_wifimgr_source_has_no_password_literals(self):
        offenders = []
        for path in _py_files():
            text = _read(path)
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                # 注释与文档字符串不算（可能是在解释为什么不用 argv）
                code = stripped.split("#", 1)[0]
                if not code.strip():
                    continue
                for m in _LITERAL_RE.finditer(code):
                    value = m.group(2)
                    if value in ALLOWED_LITERALS:
                        continue
                    # 变量引用 / 函数名（password 或 password if ... 形式）
                    if value in ("password", "req.password", "psk", "self.password"):
                        continue
                    offenders.append(
                        "%s:%d  %s"
                        % (os.path.relpath(path, ROOT), lineno, stripped[:100])
                    )
        self.assertEqual(
            offenders,
            [],
            "源码中出现疑似真实口令字面量（推送公开仓库会永久泄漏）:\n  "
            + "\n  ".join(offenders),
        )

    def test_probe_uses_placeholder_not_real_password(self):
        """SAE 探测必须用占位口令，不能用真实网络密码。"""
        text = _read(os.path.join(SRC, "backends", "nmcli.py"))
        m = re.search(r"probe_password\s*=\s*password\s*or\s*([\"'])([^\"']+)\1", text)
        self.assertIsNotNone(m, "未找到 SAE 探测的占位口令")
        self.assertIn(
            m.group(2),
            ALLOWED_LITERALS,
            "SAE 探测的默认口令必须是显式占位值，当前=%r" % m.group(2),
        )

    def test_no_real_ssid_with_password_in_source(self):
        """测试里可以出现真实 SSID（那是公开可见的广播名），但不应与口令同现。"""
        for path in _py_files():
            if _ALLOW_FILES.search(path):
                continue
            text = _read(path)
            if "88888888" in text:
                self.fail(
                    "%s 含疑似真实口令 88888888" % os.path.relpath(path, ROOT)
                )


class TestGitignoreHygiene(unittest.TestCase):
    """仓库卫生：凭据类文件不得被提交。

    只在**源码仓库**里有意义 —— 部署到 /opt/wifimgr 时不含 .gitignore，
    因此找不到就跳过，而不是让 NAS 上的 selftest 失败。
    """

    def setUp(self):
        p = os.path.join(ROOT, ".gitignore")
        if not os.path.isfile(p):
            self.skipTest("非源码仓库环境（无 .gitignore），跳过仓库卫生检查")
        with io.open(p, "r", encoding="utf-8") as fh:
            self.text = fh.read()

    def test_gitignore_exists(self):
        self.assertTrue(self.text, "缺少 .gitignore")

    def test_ignores_runtime_and_credentials(self):
        for pat in ("*.db", "*.nmconnection", "__pycache__", "*.bak-*"):
            self.assertIn(pat, self.text, ".gitignore 缺少 %s" % pat)

    def test_no_db_or_keyfiles_in_tree(self):
        """工作目录里不应残留运行时产物（否则可能被误提交）。"""
        bad = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            for f in filenames:
                if f.endswith((".db", ".db-wal", ".db-shm", ".nmconnection")):
                    bad.append(os.path.join(dirpath, f))
        self.assertEqual(bad, [], "工作目录残留运行时/凭据文件: %s" % bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
