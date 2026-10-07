"""HTTP API 业务逻辑。

刻意做成**纯函数** ``(ctx, body) -> (status, dict)``，不碰 ``http.server``。
这样全部业务分支都能在测试里直接调用，不需要起服务器 —— 而起服务器在
目标机上意味着绑端口、进 ``systemd``，不适合当单测手段。
"""

import os
import time

from . import nmkey
from .errors import AppError, NotFoundError, RateLimitedError, ValidationError
from .models import AUTH_OPEN, AUTH_SAE, AUTH_WEP, ConnectRequest


class Ctx(object):
    """运行时上下文。把依赖收拢到这里，测试可整体替换。"""

    def __init__(self, cfg, backend, store, log, guardian=None, scanner=None):
        self.cfg = cfg
        self.backend = backend
        self.store = store
        self.log = log
        self.guardian = guardian
        self.scanner = scanner  # ScanCache

    @property
    def version(self):
        from . import __version__

        return __version__


class ScanCache(object):
    """扫描结果缓存 + 限流。

    NetworkManager 对重复 ``rescan`` 有速率限制，触发后返回
    ``Scan not allowed while already running``。所以：
      * ``min_interval_sec`` 内的请求直接返回缓存，不真正扫描
      * 缓存附带 ``age_sec`` / ``stale`` 让 UI 能如实告知"这是 N 秒前的结果"
    """

    def __init__(self, min_interval=8, max_cached=45):
        self.min_interval = int(min_interval or 8)
        self.max_cached = int(max_cached or 45)
        self._items = []
        self._scanned_at = 0.0
        self._stale = False

    def age(self, now=None):
        if not self._scanned_at:
            return None
        return int((now or time.time()) - self._scanned_at)

    def due(self, now=None):
        """是否允许真正触发一次扫描。"""
        if not self._scanned_at:
            return True
        return ((now or time.time()) - self._scanned_at) >= self.min_interval

    def retry_after(self, now=None):
        """限流时还需等待多少秒。"""
        if not self._scanned_at:
            return 0
        elapsed = (now or time.time()) - self._scanned_at
        return max(1, int(self.min_interval - elapsed))

    def get(self, now=None):
        return {
            "items": self._items,
            "cached": True,
            "age_sec": self.age(now),
            "scanned_at": self._scanned_at,
            "stale": self._stale,
        }

    def put(self, items, now=None):
        self._items = list(items or [])
        self._scanned_at = now or time.time()
        self._stale = False
        return self.get(now)


# ---------------------------------------------------------------- handlers


def get_session(ctx, body=None, query=None):
    """下发 CSRF token、版本与后端信息。

    token 由 httpd 层生成（每个会话一个），这里只透传。
    """
    token = getattr(ctx, "csrf_token", None)
    return 200, {
        "csrf": token,
        "version": ctx.version,
        "backend": ctx.backend.NAME,
        "iface": (ctx.cfg.get("wifi") or {}).get("ifname", "wlan0"),
        "time": time.time(),
    }


def get_capabilities(ctx, body=None, query=None):
    caps = ctx.backend.capabilities()
    d = caps.to_dict()
    # 补充实测结论：即便配置层接受 sae，握手在本机也失败（D4）。
    # 只在 nmcli 后端上加这个说明，避免误导。
    if ctx.backend.NAME == "nmcli" and d.get("sae_configurable"):
        d.setdefault("notes", []).append(
            "本机实测：SAE 配置层可写入但真实握手失败（rtl8188fu 驱动 + 内核 4.4 限制），"
            "混合 WPA2/WPA3 的 AP 请使用 WPA2 连接"
        )
    return 200, d


def post_capabilities_refresh(ctx, body=None, query=None):
    return get_capabilities(ctx, body, query)


def get_status(ctx, body=None, query=None):
    st = ctx.backend.status()
    d = {"status": st.to_dict()}
    if ctx.store is not None:
        try:
            d["saved_count"] = ctx.store.count_saved()
        except Exception:
            d["saved_count"] = None
    if ctx.guardian is not None:
        d["guardian"] = ctx.guardian.status()
    return 200, d


def get_scan(ctx, body=None, query=None):
    q = query or {}
    refresh = str(q.get("refresh", "0")).lower() in ("1", "true", "yes")
    cache = ctx.scanner
    if refresh and not cache.due():
        raise RateLimitedError(
            "扫描过于频繁，%d 秒后可重试" % cache.retry_after(),
            retry_after=cache.retry_after(),
        )
    # 冷缓存（刚启动、还没扫过）时必须真的扫一次，
    # 否则前端首屏会看到空列表。
    if not cache.get()["items"]:
        return 200, _do_scan(ctx, cache)
    if refresh or cache.due():
        return 200, _do_scan(ctx, cache)
    return 200, cache.get()


def _do_scan(ctx, cache):
    try:
        items = ctx.backend.scan(force=True)
    except AppError as exc:
        # 扫描失败时退回上次缓存并标 stale，而不是让用户看到空白
        prev = cache.get()
        if prev["items"]:
            prev["stale"] = True
            prev["error"] = exc.to_dict()
            return prev
        raise
    # 标记已保存网络
    try:
        saved = ctx.store.list_saved_networks() if ctx.store else []
        known = set()
        for s in saved:
            known.add(s["ssid"])
            if s.get("bssid_lock"):
                known.add("%s\x00%s" % (s["ssid"], s["bssid_lock"]))
        for it in items:
            if "%s\x00%s" % (it.ssid, it.bssid) in known or it.ssid in known:
                it.saved = True
    except Exception:
        pass
    data = cache.put(items)
    # 修正 in_use：以状态判定为准，扫描结果里的 IN-USE 有滞后
    try:
        st = ctx.backend.status()
        if st.connected and st.ssid:
            for it in items:
                if it.ssid == st.ssid:
                    it.in_use = True
    except Exception:
        pass
    data["items"] = [i.to_dict(_hidden_label(ctx)) for i in items]
    return data


def _hidden_label(ctx):
    return (((ctx.cfg.get("wifi") or {}).get("scan") or {}).get("hidden_ssid_label")) or "(隐藏网络)"


def post_scan(ctx, body=None, query=None):
    cache = ctx.scanner
    if not cache.due():
        raise RateLimitedError(
            "扫描过于频繁，%d 秒后可重试" % cache.retry_after(), retry_after=cache.retry_after()
        )
    return 200, _do_scan(ctx, cache)


def post_connect(ctx, body=None, query=None):
    body = body or {}
    if not isinstance(body, dict):
        raise ValidationError("请求体必须是 JSON 对象")
    ssid = (body.get("ssid") or "").strip() if isinstance(body.get("ssid"), str) else ""
    bssid = body.get("bssid") or ""
    password = body.get("password")
    if password is not None and not isinstance(password, str):
        raise ValidationError("password 必须是字符串", field="password")
    req = ConnectRequest(
        ssid=ssid,
        bssid=bssid,
        password=password,
        auth_kind=body.get("auth_kind") or _guess_auth(body.get("security")),
        profile_name=body.get("profile_name"),
        remember=bool(body.get("remember", True)),
        sae_policy=body.get("sae_policy") or ((ctx.cfg.get("wifi") or {}).get("connect") or {}).get(
            "sae_policy", "psk_first"
        ),
        bssid_lock=bool(body.get("bssid_lock", False)),
        iface=(ctx.cfg.get("wifi") or {}).get("ifname", "wlan0"),
    )
    req.validate()
    # 日志里绝不出现密码
    ctx.log.info("api", "connect.request", "收到连接请求", req.to_public_dict())
    res = ctx.backend.connect(req)
    if ctx.store is not None:
        try:
            ctx.store.add_attempt(
                ssid=req.ssid,
                bssid=req.bssid,
                profile_name=res.profile_name or "",
                requested=res.requested_key_mgmt,
                used=res.used_key_mgmt,
                phase=res.phase,
                error_code=None,
                duration_ms=res.duration_ms,
            )
        except Exception:
            pass
    status = 200 if res.ok else 400
    return status, {"result": res.to_dict()}


def _guess_auth(security):
    s = (security or "").lower()
    if "wpa3" in s and "wpa2" in s:
        return "mixed"
    if "wpa3" in s:
        return "sae"
    if "wpa2" in s or "wpa1" in s:
        return "psk"
    if "wep" in s:
        return "wep"
    if "open" in s or not s:
        return "open"
    return "unknown"


def post_disconnect(ctx, body=None, query=None):
    res = ctx.backend.disconnect()
    return (200 if res.ok else 400), {"result": res.to_dict()}


def get_networks(ctx, body=None, query=None):
    """只返回 has_secret 布尔，**永不返回密码**。"""
    rows = ctx.store.list_saved_networks() if ctx.store else []
    out = []
    for r in rows:
        out.append(
            {
                "profile_name": r["profile_name"],
                "uuid": r.get("uuid"),
                "ssid": r["ssid"],
                "bssid_lock": r.get("bssid_lock"),
                "security": r.get("security"),
                "key_mgmt": r.get("key_mgmt"),
                "iface": r.get("iface"),
                "favorite": bool(r.get("favorite")),
                "note": r.get("note"),
                "has_secret": bool(r.get("key_mgmt") and r.get("key_mgmt") != "none"),
                "connect_count": r.get("connect_count", 0),
                "last_result": r.get("last_result"),
                "last_ok_at": r.get("last_ok_at"),
            }
        )
    return 200, {"items": out}


def put_network(ctx, body=None, query=None):
    """保存/更新一个网络。**密码唯一流向 keyfile 的入口，不入库。**"""
    body = body or {}
    q = query or {}
    profile_name = body.get("profile_name") or q.get("profile_name")
    if not profile_name:
        raise ValidationError("缺少 profile_name", field="profile_name")
    ssid = body.get("ssid") or ""
    password = body.get("password")
    key_mgmt = body.get("key_mgmt") or body.get("auth_kind") or "wpa-psk"
    if key_mgmt in ("psk", "wpa-psk"):
        key_mgmt = "wpa-psk"
    bssid = body.get("bssid") or ""
    remember = bool(body.get("remember", True))

    if key_mgmt != "none" and not password:
        # 允许不传密码：表示「沿用 NM keyfile 里已有的」
        if not ctx.backend.profile_exists(profile_name):
            raise ValidationError("新网络必须提供密码", field="password")

    applied = ctx.backend.apply_profile(
        profile_name=profile_name,
        ssid=ssid,
        password=password if password else None,
        key_mgmt=key_mgmt,
        bssid=bssid,
        remember=remember,
        bssid_lock=bool(body.get("bssid_lock", False)),
        store=ctx.store,
    )
    if body.get("favorite") is not None and ctx.store:
        ctx.store.set_favorite(profile_name, bool(body["favorite"]))
    return 200, {"profile_name": profile_name, "saved": True, "nm": applied}


def delete_network(ctx, body=None, query=None):
    q = query or {}
    b = body or {}
    profile_name = q.get("profile_name") or b.get("profile_name")
    if not profile_name:
        raise ValidationError("缺少 profile_name", field="profile_name")
    if ctx.store is not None and not ctx.store.is_managed(profile_name):
        raise ValidationError(
            "该 profile 不是本应用创建的，拒绝删除",
            detail={"profile": profile_name},
        )
    removed = ctx.backend.delete_profile(profile_name)
    if ctx.store is not None:
        ctx.store.delete_saved_network(profile_name)
    return 200, {"deleted": True, "nm_profile_removed": bool(removed)}


def post_network_connect(ctx, body=None, query=None):
    """用已保存的凭据重连（密码从 NM keyfile 读，**不经过数据库**）。"""
    q = query or {}
    b = body or {}
    profile_name = q.get("profile_name") or b.get("profile_name")
    if not profile_name:
        raise ValidationError("缺少 profile_name", field="profile_name")
    if not ctx.backend.profile_exists(profile_name):
        raise NotFoundError("profile 不存在: %s" % profile_name)
    res = ctx.backend.activate_profile(profile_name)
    if ctx.store is not None:
        try:
            ctx.store.record_connect_result(profile_name, res.ok, res.phase)
        except Exception:
            pass
    return (200 if res.ok else 400), {"result": res.to_dict()}


def get_daemon(ctx, body=None, query=None):
    if ctx.guardian is None:
        return 200, {"enabled": False, "runtime": {"running": False}}
    return 200, {"config": ctx.guardian.config(), "runtime": ctx.guardian.status()}


def put_daemon(ctx, body=None, query=None):
    if ctx.guardian is None:
        raise AppError("INTERNAL", "守护线程未启用")
    updates = (body or {}).get("config") or body or {}
    saved = ctx.guardian.apply_config(updates)
    if ctx.store is not None:
        try:
            ctx.store.set_setting("daemon", saved)
        except Exception:
            pass
    return 200, {"config": saved}


def get_events(ctx, body=None, query=None):
    q = query or {}
    try:
        limit = max(1, min(500, int(q.get("limit") or 100)))
    except (TypeError, ValueError):
        limit = 100
    level = q.get("level")
    if ctx.store is not None:
        items = ctx.store.list_events(limit=limit, level=level)
    else:
        items = []
    nxt = 0
    if items:
        nxt = max(int(i.get("id") or 0) for i in items)
    return 200, {"items": items, "next_since": nxt}


def get_doctor(ctx, body=None, query=None):
    checks = []
    try:
        checks = [{"name": n, "ok": bool(ok), "detail": str(d)} for (n, ok, d) in ctx.backend.self_test()]
    except Exception as exc:
        checks.append({"name": "backend self_test", "ok": False, "detail": str(exc)})

    # 数据库
    try:
        if ctx.store:
            size = ctx.store.db_size_bytes()
            checks.append(
                {"name": "数据库", "ok": True, "detail": "%s (%d 字节)" % (ctx.store.path, size)}
            )
    except Exception as exc:
        checks.append({"name": "数据库", "ok": False, "detail": str(exc)})

    # 磁盘可写（只读/满 -> 连接功能会失效）
    for label, path in (
        ("状态目录", ((ctx.cfg.get("runtime") or {}).get("data_dir") or "/var/lib/wifimgr")),
        ("keyfiles 目录", ((ctx.cfg.get("wifi") or {}).get("connect") or {}).get("keyfiles_dir")),
    ):
        try:
            ok = os.path.isdir(path) and os.access(path, os.W_OK)
            checks.append({"name": label, "ok": ok, "detail": path})
        except Exception as exc:
            checks.append({"name": label, "ok": False, "detail": str(exc)})

    # 遗留 watchdog 检测（部署后应已停用）
    try:
        cron = "/etc/cron.d/wifi-check"
        if os.path.isfile(cron):
            with open(cron, "r", encoding="utf-8", errors="replace") as fh:
                body_txt = fh.read()
            active = [
                ln
                for ln in body_txt.splitlines()
                if ln.strip() and not ln.strip().startswith("#") and "wifi-check.sh" in ln
            ]
            checks.append(
                {
                    "name": "遗留 watchdog",
                    "ok": not active,
                    "detail": "已停用" if not active else "仍在运行: %s" % (active[0][:80]),
                }
            )
    except Exception:
        pass

    return 200, {"checks": checks, "backend": ctx.backend.NAME, "version": ctx.version}


ROUTES = {
    ("GET", "/api/v1/session"): get_session,
    ("GET", "/api/v1/capabilities"): get_capabilities,
    ("POST", "/api/v1/capabilities/refresh"): post_capabilities_refresh,
    ("GET", "/api/v1/status"): get_status,
    ("GET", "/api/v1/scan"): get_scan,
    ("POST", "/api/v1/scan"): post_scan,
    ("POST", "/api/v1/connect"): post_connect,
    ("POST", "/api/v1/disconnect"): post_disconnect,
    ("GET", "/api/v1/networks"): get_networks,
    ("PUT", "/api/v1/networks"): put_network,
    ("DELETE", "/api/v1/networks"): delete_network,
    ("POST", "/api/v1/networks/connect"): post_network_connect,
    ("GET", "/api/v1/daemon"): get_daemon,
    ("PUT", "/api/v1/daemon"): put_daemon,
    ("GET", "/api/v1/events"): get_events,
    ("GET", "/api/v1/doctor"): get_doctor,
}
