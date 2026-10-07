"""前端静态资源测试（无浏览器依赖）。

起因：用户报「一直转圈正在切换网络」。根因是 CSS 里
``.overlay { display: flex }`` 覆盖了 HTML 的 ``hidden`` 属性 ——
``[hidden]`` 靠 UA 样式表的 ``display: none`` 实现，任何显式 display 都会覆盖它。
于是 JS 的 ``el.hidden = true`` 生效但元素仍显示，遮罩永远关不掉。

这类 bug 单靠「页面能打开」测不出来，所以这里做静态断言：
凡是带 ``hidden`` 属性的元素，其 class 在 CSS 里不得有显式 display 规则
（除非全局有 ``[hidden] { display: none !important }`` 兜底）。
"""

import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "wifimgr", "static")
HTML = os.path.join(STATIC, "index.html")
CSS = os.path.join(STATIC, "app.css")
JS = os.path.join(STATIC, "app.js")


def read(path):
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _try_read(path):
    try:
        return read(path)
    except (IOError, OSError, UnicodeDecodeError):
        return ""


class TestStaticFilesExist(unittest.TestCase):
    def test_all_present(self):
        for p in (HTML, CSS, JS):
            self.assertTrue(os.path.isfile(p), "缺少文件: %s" % p)

    def test_not_empty(self):
        for p in (HTML, CSS, JS):
            self.assertGreater(len(_try_read(p)), 100, "%s 内容过短" % p)


class TestHiddenAttributeCssConflict(unittest.TestCase):
    """核心回归测试：hidden 属性必须真的能隐藏元素。"""

    def _css_has_hidden_guard(self):
        css = _try_read(CSS)
        return bool(re.search(r"\[hidden\]\s*\{[^}]*display\s*:\s*none\s*!important", css))

    def test_global_hidden_guard_exists(self):
        """必须有 [hidden] { display: none !important } 兜底。"""
        self.assertTrue(
            self._css_has_hidden_guard(),
            "CSS 缺少 [hidden] { display: none !important } 兜底规则："
            "带 display:flex 的元素（.modal/.overlay）上的 hidden 属性会失效",
        )

    def test_no_element_with_hidden_has_explicit_display(self):
        """带 hidden 属性的元素，其 class 不得声明显式 display（除非有全局兜底）。"""
        if self._css_has_hidden_guard():
            self.skipTest("已有全局 [hidden] 兜底规则，display 冲突被消解")
        html = _try_read(HTML)
        css = _try_read(CSS)
        offenders = []
        for m in re.finditer(
            r'<(\w+)[^>]*class="([^"]+)"[^>]*\shidden(?=[\s>])', html
        ):
            classes = m.group(2).split()
            for cls in classes:
                rule = re.search(r"\.%s\s*\{([^}]*)\}" % re.escape(cls), css)
                if rule and "display" in rule.group(1):
                    offenders.append("<%s class=%s> 的 CSS 含 display: %s" % (
                        m.group(1), cls, rule.group(1).strip()))
        self.assertEqual(offenders, [], "hidden 属性会被 CSS 覆盖: %s" % offenders)


class TestOverlaySafety(unittest.TestCase):
    """遮罩必须有多条保险，不能只有一条失败路径。"""

    def setUp(self):
        self.js = _try_read(JS)

    def test_show_and_hide_both_toggle_display(self):
        """showOverlay/hideOverlay 都要同时处理 hidden 与 inline style。"""
        show = re.search(r"function showOverlay\(.*?\n  \}", self.js, re.S)
        hide = re.search(r"function hideOverlay\(.*?\n  \}", self.js, re.S)
        self.assertIsNotNone(show, "缺少 showOverlay")
        self.assertIsNotNone(hide, "缺少 hideOverlay")
        self.assertIn(".hidden = false", show.group(0), "showOverlay 未设置 hidden=false")
        self.assertIn(".hidden = true", hide.group(0), "hideOverlay 未设置 hidden=true")
        self.assertIn('style.display', show.group(0), "showOverlay 未清 inline display")
        self.assertIn('style.display', hide.group(0), "hideOverlay 未设 inline display")

    def test_functions_defined_once(self):
        """重复定义会让旧版本覆盖新版本（曾因此留下有 bug 的 hideOverlay）。"""
        for fn in ("esc", "showOverlay", "hideOverlay", "api", "openPassword", "closePassword"):
            n = len(re.findall(r"function %s\(" % fn, self.js))
            self.assertEqual(n, 1, "函数 %s 定义了 %d 次，应为 1 次" % (fn, n))

    def test_has_timeout_wrapper(self):
        """必须有带超时的 fetch 包装，否则后端挂住用户就永久等待。"""
        self.assertIn("function apiWithTimeout(", self.js, "缺少 apiWithTimeout")
        self.assertIn("AbortController", self.js, "apiWithTimeout 未使用 AbortController")
        self.assertIn("AbortError", self.js, "未处理 AbortError")

    def test_has_watchdog(self):
        """必须有兜底看门狗，防止回调被吞导致遮罩永久停留。"""
        self.assertIn("shownAt", self.js, "缺少遮罩时间戳")
        self.assertIn("看门狗", self.js, "缺少兜底看门狗说明")

    def test_escape_dismisses_overlay(self):
        self.assertIn("Escape", self.js, "未绑定 Escape 键")
        self.assertIn("hideOverlay", self.js)

    def test_connect_uses_timeout(self):
        """连接请求必须走带超时的路径（它最慢）。"""
        m = re.search(r'apiWithTimeout\("POST", "/connect"', self.js)
        self.assertIsNotNone(m, "POST /connect 未使用 apiWithTimeout")

    def test_poll_skips_when_overlay_shown(self):
        """遮罩显示时轮询会堆积（每次 status 都要 2 次 nmcli 调用）。"""
        self.assertIn('$("overlay").hidden', self.js, "轮询未检查遮罩状态")


class TestHtmlSanity(unittest.TestCase):
    def setUp(self):
        self.html = _try_read(HTML)

    def test_prefix_matches_config(self):
        """前端 PREFIX 必须与 /etc/wifimgr.json 的 url_prefix 一致。"""
        js = _try_read(JS)
        m = re.search(r'var PREFIX = "([^"]+)"', js)
        self.assertIsNotNone(m, "未找到 PREFIX 定义")
        self.assertEqual(
            m.group(1),
            "/wifi",
            "PREFIX 与部署配置(/wifi)不一致会导致 404",
        )

    def test_api_path_built_from_prefix(self):
        js = _try_read(JS)
        self.assertIn('var API = PREFIX + "/api/v1"', js)

    def test_overlay_and_modal_present(self):
        self.assertIn('id="overlay"', self.html)
        self.assertIn('id="pwdModal"', self.html)

    def test_has_viewport_meta(self):
        """手机端必须声明 viewport，否则页面会被缩放。"""
        self.assertIn("viewport", self.html)

    def test_external_scripts_avoidable(self):
        """不应依赖外部 CDN —— NAS 可能不通外网。"""
        html = _try_read(HTML)
        for bad in ("cdn.", "unpkg", "jsdelivr", "googleapis"):
            self.assertNotIn(bad, html, "页面引用了外部资源 %s（本机可能不通外网）" % bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
