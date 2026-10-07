"""CSRF 防护与静态文件安全。

面板没有登录页（只监听 127.0.0.1 + nginx，局域网可信），但仍需要 CSRF：
恶意网页可以向 ``http://192.168.31.47/wifi/api/v1/disconnect`` 发跨站请求，
把 NAS 的 WiFi 切掉。``SameSite=Strict`` + 双提交 token 足以挡住这一类。
"""

import hmac
import os
import posixpath
import re
import secrets

from .errors import CsrfError

# 静态资源相对路径白名单：只允许这些字符，杜绝 ../ 之类
_SAFE_REL_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".webmanifest": "application/manifest+json",
}


class CsrfGuard(object):
    """双提交 token。每个会话一个随机 token。"""

    def __init__(self, cfg):
        c = (cfg.get("http") or {}).get("csrf") or {}
        self.enabled = bool(c.get("enabled", True))
        self.cookie_name = c.get("cookie_name") or "wifimgr_csrf"
        self.header_name = c.get("header_name") or "X-CSRF-Token"
        self.require_origin = bool(c.get("require_origin_match", True))
        self.token = secrets.token_urlsafe(32)

    def check(self, method, headers, cookies, origin_host=None):
        """写操作前校验。``headers``/``cookies`` 是普通 dict（大小写已归一）。"""
        if not self.enabled:
            return True
        if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return True
        cookie = cookies.get(self.cookie_name) or ""
        header = headers.get(self.header_name.lower()) or headers.get(self.header_name) or ""
        if not (cookie and header):
            raise CsrfError("缺少 CSRF token（cookie 或 header）")
        if not hmac.compare_digest(str(cookie), str(header)):
            raise CsrfError("CSRF token 不匹配")
        if self.require_origin:
            origin = headers.get("origin") or ""
            referer = headers.get("referer") or ""
            check = origin or referer
            if check and origin_host:
                # 只比对 host 部分，容忍 http/https 与端口差异
                got = _host_of(check)
                if got and origin_host and got != origin_host:
                    raise CsrfError("Origin 不在允许列表: %r" % got)
        return True


def _host_of(url):
    if not url:
        return ""
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+)", url)
    return m.group(1).lower() if m else ""


def resolve_static(static_dir, url_path):
    """把 URL 路径安全地映射到静态目录内的文件。

    **不使用** ``SimpleHTTPRequestHandler``（它就是目录穿越的常见来源）。
    这里做三层防护：字符白名单 → ``normpath`` 消解 ``..`` → realpath 前缀校验。
    返回 ``(abs_path, mime)``；不安全或不存在时返回 ``None``。
    """
    if not url_path or url_path == "/":
        url_path = "/index.html"
    # 去掉 query
    url_path = url_path.split("?", 1)[0].split("#", 1)[0]
    # URL 解码（%2e%2e 之类）
    from urllib.parse import unquote

    url_path = unquote(url_path)
    rel = url_path.lstrip("/")
    if not rel:
        rel = "index.html"
    if not _SAFE_REL_RE.match(rel):
        return None
    if "\x00" in rel or "\\" in rel:
        return None
    # 逐段消解，任何 .. 直接拒绝（不靠 normpath 兜底）
    parts = []
    for seg in rel.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            return None
        parts.append(seg)
    rel = "/".join(parts)
    if not rel:
        return None

    base = os.path.realpath(static_dir)
    target = os.path.realpath(os.path.join(base, rel))
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None
    ext = os.path.splitext(target)[1].lower()
    mime = MIME.get(ext, "application/octet-stream")
    return target, mime


def read_static(static_dir, url_path):
    """读取静态文件，返回 ``(bytes, mime, etag)``。不安全/不存在返回 None。"""
    resolved = resolve_static(static_dir, url_path)
    if resolved is None:
        return None
    target, mime = resolved
    try:
        with open(target, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    st = os.stat(target)
    etag = '"%x-%x"' % (int(st.st_mtime), st.st_size)
    return data, mime, etag
