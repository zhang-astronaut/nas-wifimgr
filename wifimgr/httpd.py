"""HTTP 服务（纯标准库 http.server）。

``http.server`` 只是"能用"，上线必须加固的点：

* ``ThreadingHTTPServer`` —— 默认单线程，一个慢请求会阻塞全站
* ``protocol_version = HTTP/1.1`` —— **必须**每个响应都写准确 Content-Length，
  否则 keep-alive 连接会悬挂
* POST 先校验 ``Content-Length`` 上限，再**精确读取** N 字节；多读会让下一个
  请求在 keep-alive 上收到垃圾数据而 400
* 静态文件自己实现，不用 ``SimpleHTTPRequestHandler``
* 每线程独立 sqlite 连接，用完在 finally 里关闭
* 统一 JSON 错误形状
"""

import json
import os
import re
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import api as apimod
from .errors import AppError
from .security import CsrfGuard, read_static


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # 避免慢客户端把 backlog 占满
    request_queue_size = 32

    def handle_error(self, request, client_address):
        # 客户端断开（BrokenPipe/Reset）不是服务端错误，不要刷栈
        import sys

        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wifimgr"
    sys_version = ""  # 不泄露 Python 版本

    # 由 serve() 注入
    ctx = None
    csrf = None
    log = None
    static_dir = None
    show_server_header = False

    # ---------- 基础 ----------
    def log_message(self, fmt, *args):
        """覆盖默认 stderr 噪音；走我们的 logbus，且不打请求体。"""
        if Handler.log is None:
            return
        # 只记异常类（4xx/5xx），正常请求不记
        try:
            code = int(str(args[1])) if len(args) > 1 else 0
        except (ValueError, IndexError):
            code = 0
        if code >= 400:
            Handler.log.warn("http", "request", fmt % args)

    def _host(self):
        return (self.headers.get("Host") or "").split(":")[0].lower()

    def _cookies(self):
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        return out

    def _headers_lower(self):
        return {k.lower(): v for k, v in self.headers.items()}

    def _send(self, status, body=b"", content_type="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            if Handler.show_server_header:
                self.send_header("Server", self.server_version)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, payload, extra=None):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra)

    def _error(self, exc, request_id=None):
        if isinstance(exc, AppError):
            payload = {
                "ok": False,
                "error": exc.to_dict(request_id=request_id, ts=time.time()),
            }
            status = 400
            if exc.code == "CSRF_FAILED":
                status = 403
            elif exc.code in ("UNAUTHORIZED",):
                status = 401
            elif exc.code == "NOT_FOUND":
                status = 404
            elif exc.code == "CONFLICT":
                status = 409
            elif exc.code == "RATE_LIMITED":
                status = 429
            elif exc.code in ("BUSY", "NMCLI_TIMEOUT", "DBUS_TIMEOUT", "DB_ERROR", "WLAN0_BUSY"):
                status = 503
            elif exc.code == "INTERNAL":
                status = 500
            retry_after = (exc.detail or {}).get("retry_after")
            extra = {"Retry-After": str(int(retry_after))} if retry_after else None
            self._json(status, payload, extra)
            return
        if Handler.log:
            Handler.log.error("http", "internal", "未捕获异常", {"err": str(exc)})
        self._json(
            500,
            {
                "ok": False,
                "error": {
                    "code": "INTERNAL",
                    "message": "内部错误",
                    "detail": {},
                    "retryable": False,
                    "hint": None,
                    "request_id": request_id,
                    "ts": time.time(),
                },
            },
        )

    # ---------- 请求体 ----------
    def _read_body(self):
        raw_limit = None
        if Handler.ctx is not None:
            raw_limit = ((Handler.ctx.cfg.get("http") or {}) or {}).get("body_max_bytes")
        limit = int(raw_limit or 16384)
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return {}
        try:
            n = int(raw_len)
        except ValueError:
            raise AppError("BAD_REQUEST", "Content-Length 非法")
        if n < 0:
            raise AppError("BAD_REQUEST", "Content-Length 为负")
        if n > limit:
            # 不读 body 直接断开，避免大包打满内存
            raise AppError("BAD_REQUEST", "请求体过大（上限 %d 字节）" % limit)
        if n == 0:
            return {}
        # 精确读 n 字节：多读会在 keep-alive 上留下垃圾导致下一个请求 400
        data = self.rfile.read(n)
        if len(data) != n:
            raise AppError("BAD_REQUEST", "请求体不完整")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppError("BAD_REQUEST", "JSON 解析失败: %s" % exc)
        if parsed is None:
            return {}
        if not isinstance(parsed, (dict, list)):
            raise AppError("BAD_REQUEST", "请求体必须是 JSON 对象")
        return parsed

    def _query(self):
        from urllib.parse import parse_qs, urlparse

        u = urlparse(self.path)
        return {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}

    # ---------- 分发 ----------
    def _handle(self, method):
        request_id = "%x" % int(time.time() * 1000)
        path = self.path.split("?", 1)[0]
        # 去掉可能的 url_prefix（nginx 通常已剥离，双保险）
        prefix = ((Handler.ctx.cfg.get("http") or {}).get("url_prefix") if Handler.ctx else "") or ""
        if prefix and path.startswith(prefix):
            path = path[len(prefix) :] or "/"
        if not path.startswith("/"):
            path = "/" + path

        # 静态资源
        if method in ("GET", "HEAD") and not path.startswith("/api/"):
            return self._serve_static(path)

        key = (method, path)
        handler = apimod.ROUTES.get(key)
        if handler is None:
            # 兼容 /api/v1/networks/<name>/connect 形式
            m = _match_deep(key)
            if m:
                handler = m
            else:
                return self._json(
                    404,
                    {
                        "ok": False,
                        "error": {
                            "code": "NOT_FOUND",
                            "message": "无此接口: %s %s" % (method, path),
                            "detail": {},
                            "retryable": False,
                            "hint": None,
                            "request_id": None,
                            "ts": time.time(),
                        },
                    },
                )
        try:
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                Handler.csrf.check(
                    method, self._headers_lower(), self._cookies(), self._host()
                )
            body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
            query = self._query()
            status, payload = handler(Handler.ctx, body=body, query=query)
            out = {"ok": True, "data": payload}
            extra = None
            # session 顺带下发 csrf cookie
            if path == "/api/v1/session" and payload.get("csrf") and Handler.csrf.enabled:
                extra = {
                    "Set-Cookie": "%s=%s; Path=%s; SameSite=Strict"
                    % (Handler.csrf.cookie_name, payload["csrf"], prefix or "/")
                }
            self._json(status, out, extra)
        except AppError as exc:
            self._error(exc, request_id)
        except Exception as exc:
            self._error(exc, request_id)
        finally:
            # per-thread sqlite 连接用完就关，否则线程池会积累连接
            store = getattr(Handler.ctx, "store", None)
            if store is not None:
                try:
                    store.close_thread_conn()
                except Exception:
                    pass

    def _serve_static(self, path):
        got = read_static(Handler.static_dir, path)
        if got is None:
            # SPA 回退：仅对「看起来是前端路由」的请求生效。
            # 含 .. 或编码过的穿越痕迹一律 404 —— 否则 /../../etc/passwd 会
            # 拿到 index.html 的 200，虽然没泄漏，但语义上是在掩盖攻击尝试。
            low = path.lower()
            suspicious = (".." in path) or ("%2e" in low) or ("%2f" in low) or ("%5c" in low)
            tail = path.rsplit("/", 1)[-1]
            if not suspicious and "." not in tail:
                got = read_static(Handler.static_dir, "/index.html")
            if got is None:
                return self._json(
                    404,
                    {
                        "ok": False,
                        "error": {
                            "code": "NOT_FOUND",
                            "message": "页面不存在",
                            "detail": {},
                            "retryable": False,
                            "hint": None,
                            "request_id": None,
                            "ts": time.time(),
                        },
                    },
                )
        data, mime, etag = got
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(200, data, mime, {"ETag": etag})

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")


def _match_deep(key):
    """匹配 ``/api/v1/networks/<profile>/connect`` 这类带参数路径。

    返回一个把 profile_name 塞进 query 的包装函数。
    """
    from urllib.parse import unquote

    method, path = key
    if method == "POST":
        m = re.match(r"^/api/v1/networks/(.+)/connect$", path)
        if m:
            name = unquote(m.group(1))

            def h(ctx, body=None, query=None):
                q = dict(query or {})
                q["profile_name"] = name
                return apimod.post_network_connect(ctx, body=body, query=q)

            return h

    #删除。必须独立于上面的 POST 分支：曾经被误写在 `if method == "POST"`
    # 之内，导致 DELETE 永远匹配不到、前端报「无此接口」(404)。
    if method == "DELETE":
        m = re.match(r"^/api/v1/networks/([^/]+)$", path)
        if m:
            name = unquote(m.group(1))

            def h(ctx, body=None, query=None):
                q = dict(query or {})
                q["profile_name"] = name
                return apimod.delete_network(ctx, body=body, query=q)

            return h
    return None


def serve(cfg, ctx, log, host=None, port=None):
    """启动 HTTP 服务，阻塞直到 KeyboardInterrupt。"""
    http_cfg = cfg.get("http") or {}
    host = host or http_cfg.get("listen_host") or "127.0.0.1"
    port = int(port or http_cfg.get("listen_port") or 8791)
    static_dir = http_cfg.get("static_dir") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "static"
    )
    Handler.ctx = ctx
    Handler.log = log
    Handler.static_dir = static_dir
    Handler.csrf = CsrfGuard(cfg)
    Handler.show_server_header = bool(http_cfg.get("server_header", False))
    ctx.csrf_token = Handler.csrf.token

    httpd = _ThreadingHTTPServer((host, port), Handler)
    log.info("http", "listen", "HTTP 服务已启动", {"host": host, "port": port, "static": static_dir})
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        log.info("http", "stop", "收到中断，退出")
    finally:
        httpd.server_close()
    return True
