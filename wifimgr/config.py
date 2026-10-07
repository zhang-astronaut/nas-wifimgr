"""配置加载：JSONC（允许 ``//`` 与 ``/* */`` 注释）+ 默认值合并 + 原子写。

优先级：内置默认 < 配置文件 < SQLite ``setting`` 表（UI 可改项）。

选 JSONC 而非 INI 的原因：退避三参数、能力开关、SSID→profile 映射都是嵌套结构，
用 INI 得发明多层语法；而 Python 3.8 有 ``json`` 没有 ``tomllib``。
"""

import copy
import json
import os
import re

DEFAULTS = {
    "schema_version": 1,
    "http": {
        "listen_host": "127.0.0.1",
        "listen_port": 8791,
        "url_prefix": "/wifi",
        "body_max_bytes": 16384,
        "server_header": False,
        "csrf": {
            "enabled": True,
            "cookie_name": "wifimgr_csrf",
            "header_name": "X-CSRF-Token",
            "require_origin_match": True,
        },
    },
    "wifi": {
        "ifname": "wlan0",
        "backend": "auto",
        "scan": {
            "min_interval_sec": 8,
            "max_cached_sec": 45,
            "command_timeout_sec": 20,
            "hidden_ssid_label": "(隐藏网络)",
        },
        "connect": {
            "command_timeout_sec": 60,
            "settle_sec": 8,
            # 因实测：SAE 配置层可写但握手必失败 → 默认 psk 优先
            "sae_policy": "psk_first",
            "keyfiles_dir": "/etc/NetworkManager/system-connections",
            "snapshot_dir": "/var/lib/wifimgr/keyfile-snapshots",
            "snapshot_keep": 20,
        },
    },
    "daemon": {
        "enabled": True,
        "interval_sec": 60,
        "max_retries": 6,
        "backoff": {"base_sec": 5, "factor": 2.0, "cap_sec": 300, "jitter": 0.2},
        "settle_grace_sec": 20,
        "stable_cycles_to_reset": 2,
        "flap_window_sec": 900,
        "flap_threshold": 4,
        "flap_pause_sec": 600,
        "lockfile": "/run/wifimgr-daemon.lock",
        # 空 = 自动挑信号最好的已存网络。
        # 原因：遗留 RD08_IoT 指向已不存在的 SSID，写死会导致每轮空等 25s。
        "active_profile": "",
        "fallback_profile": "",
        "dry_run": True,
    },
    "runtime": {
        "data_dir": "/var/lib/wifimgr",
        "event_retention_days": 30,
        "max_attempt_rows": 2000,
        "log_level": "info",
    },
}

_LINE_COMMENT = re.compile(r"^\s*//")
_BLOCK_START = re.compile(r"/\*")
_BLOCK_END = re.compile(r"\*/")


def strip_jsonc(text):
    """去掉 ``//`` 行注释与 ``/* */`` 块注释，保留字符串字面量内的内容。

    不能用正则直接全局替换：SSID 里完全可能出现 ``//``（例如 ``a//b``）或 ``/*``。
    所以逐字符扫描并跟踪字符串状态。
    """
    out = []
    i = 0
    n = len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def deep_merge(base, override):
    """递归合并。``override`` 中 ``None`` 不覆盖已有值（便于 UI 局部更新）。"""
    if not isinstance(base, dict) or not isinstance(override, dict):
        return copy.deepcopy(override)
    result = copy.deepcopy(base)
    for k, v in override.items():
        if v is None:
            continue
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def load(path=None, overrides=None):
    """加载配置：默认值 < 文件 < ``overrides``。"""
    cfg = copy.deepcopy(DEFAULTS)
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = strip_jsonc(fh.read())
        if raw.strip():
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("配置根节点必须是对象: %s" % path)
            cfg = deep_merge(cfg, data)
    if overrides:
        cfg = deep_merge(cfg, overrides)
    validate(cfg)
    return cfg


def validate(cfg):
    """范围校验。宁可启动失败也不要带着离谱配置跑起来。"""
    http = cfg.get("http") or {}
    port = int(http.get("listen_port") or 0)
    if not (1 <= port <= 65535):
        raise ValueError("http.listen_port 非法: %r" % (port,))

    wifi = cfg.get("wifi") or {}
    ifname = wifi.get("ifname")
    if not ifname or not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", str(ifname)):
        raise ValueError("wifi.ifname 非法: %r" % (ifname,))
    if (wifi.get("backend") or "auto") not in ("auto", "nmcli", "wpasupplicant"):
        raise ValueError("wifi.backend 只能是 auto/nmcli/wpasupplicant")

    d = cfg.get("daemon") or {}
    if int(d.get("interval_sec") or 0) < 5:
        raise ValueError("daemon.interval_sec 不得小于 5 秒")
    if int(d.get("max_retries") or 0) < 0:
        raise ValueError("daemon.max_retries 不得为负")
    bo = d.get("backoff") or {}
    if float(bo.get("base_sec") or 0) <= 0:
        raise ValueError("daemon.backoff.base_sec 必须为正")
    if float(bo.get("factor") or 0) < 1:
        raise ValueError("daemon.backoff.factor 不得小于 1")
    if float(bo.get("cap_sec") or 0) < float(bo.get("base_sec") or 0):
        raise ValueError("daemon.backoff.cap_sec 不得小于 base_sec")
    j = float(bo.get("jitter") or 0)
    if not (0 <= j <= 1):
        raise ValueError("daemon.backoff.jitter 需在 0..1 之间")
    return True


def save_atomic(path, cfg):
    """原子写：同目录临时文件 → fsync → ``os.replace`` → fsync(dir)。

    同目录是必要的：跨文件系统的 ``os.replace`` 不是原子的。
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, ".%s.tmp" % os.path.basename(path))
    body = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    try:
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        # 某些文件系统不支持目录 fsync，不影响原子性本身
        pass
    return True


def get_path(cfg, key, default=None):
    """点号取值：``get_path(cfg, "daemon.backoff.base_sec")``。"""
    cur = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def set_path(cfg, key, value):
    parts = key.split(".")
    cur = cfg
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value
    return cfg
