"""命令行入口：``python3 -m wifimgr <子命令>``。

子命令：
  serve       启动 HTTP 服务（systemd 用这个）
  scan        命令行扫描
  status      命令行看状态
  connect     连接网络（``--ask-pass`` 从 stdin 读，不进 argv）
  doctor      环境自检
  selftest    跑离线单元测试
  probe-sae   探测 SAE 配置层支持（不碰真实网络）
"""

import argparse
import getpass
import json
import os
import sys

from . import __version__, config, nmkey
from .api import ScanCache
from .backends import auto_detect
from .errors import AppError
from .logbus import LogBus
from .store import Store


def _build(args):
    cfg = config.load(getattr(args, "config", None))
    log = LogBus(
        ident="wifimgr",
        buffer_size=int((cfg.get("daemon") or {}).get("event_buffer_size") or 500),
        level=(cfg.get("runtime") or {}).get("log_level") or "info",
        use_syslog=not getattr(args, "no_syslog", False),
    )
    data_dir = (cfg.get("runtime") or {}).get("data_dir") or "/var/lib/wifimgr"
    store = None
    try:
        store = Store(os.path.join(data_dir, "wifimgr.db"), log=log)
    except Exception as exc:
        log.warn("cli", "store.failed", "数据库不可用，仅只读模式", {"err": str(exc)})
    backend = auto_detect(cfg, log, force=getattr(args, "backend", None))
    if hasattr(backend, "set_busy_lock"):
        from .runner import BusyLock

        backend.set_busy_lock(BusyLock(timeout=5.0))
    if store is not None and hasattr(backend, "set_store"):
        backend.set_store(store)
    if hasattr(backend, "store"):
        backend.store = store
    return cfg, log, backend, store


def _emit(data, as_json=True):
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    else:
        print(data)


def cmd_serve(args):
    from .api import Ctx
    from .daemon import Guardian
    from .httpd import serve

    cfg, log, backend, store = _build(args)
    http_cfg = cfg.get("http") or {}
    if not http_cfg.get("static_dir"):
        http_cfg["static_dir"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    cfg["http"] = http_cfg

    daemon = None
    dcfg = cfg.get("daemon") or {}
    if dcfg.get("enabled"):
        daemon = Guardian(cfg, backend, store, log)
        daemon.start()
    ctx = Ctx(cfg, backend, store, log, guardian=daemon, scanner=ScanCache(
        (cfg.get("wifi", {}).get("scan") or {}).get("min_interval_sec", 8),
        (cfg.get("wifi", {}).get("scan") or {}).get("max_cached_sec", 45),
    ))
    try:
        serve(cfg, ctx, log)
    finally:
        if daemon:
            daemon.stop()
        if store:
            store.close_all()
    return 0


def cmd_scan(args):
    cfg, log, backend, store = _build(args)
    try:
        items = backend.scan(force=not args.cached)
    except AppError as exc:
        print(json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False, indent=2))
        return 2
    out = []
    for i in items:
        d = i.to_dict(((cfg.get("wifi", {}).get("scan") or {}).get("hidden_ssid_label")))
        out.append(d)
    if args.json:
        _emit({"ok": True, "data": {"items": out, "count": len(out)}})
    else:
        print("%-24s %-17s %-6s %-12s %s" % ("SSID", "BSSID", "信号", "加密", "状态"))
        for d in out:
            mark = "已连接" if d["in_use"] else ""
            print(
                "%-24s %-17s %-6s %-12s %s"
                % (d["display"][:24], d["bssid"], d["signal"] if d["signal"] is not None else "-", d["security"], mark)
            )
        print("\n共 %d 个网络" % len(out))
    return 0


def cmd_status(args):
    cfg, log, backend, store = _build(args)
    st = backend.status()
    print(json.dumps({"ok": True, "data": st.to_dict()}, ensure_ascii=False, indent=2))
    return 0


def cmd_connect(args):
    from .models import ConnectRequest

    cfg, log, backend, store = _build(args)
    password = args.password
    if args.ask_pass:
        # 从 stdin 读，不出现在 argv / ps 里
        password = getpass.getpass("请输入 %s 的密码: " % args.ssid)
    req = ConnectRequest(
        ssid=args.ssid,
        bssid=args.bssid or "",
        password=password,
        auth_kind=args.auth_kind,
        remember=not args.no_remember,
        bssid_lock=bool(args.bssid_lock),
        sae_policy=args.sae_policy,
        iface=(cfg.get("wifi") or {}).get("ifname", "wlan0"),
    )
    try:
        res = backend.connect(req)
    except AppError as exc:
        print(json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False, indent=2))
        return 2
    # ConnectResult 直接铺在顶层，便于命令行/脚本判断
    print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2, default=str))
    if store:
        try:
            store.close_all()
        except Exception:
            pass
    return 0 if res.ok else 1


def cmd_profiles(args):
    cfg, log, backend, store = _build(args)
    items = backend.list_profiles()
    print("%-24s %-38s %-10s %-8s %s" % ("NAME", "UUID", "KEY-MGMT", "AUTOCONN", "IFACE"))
    for p in items:
        print(
            "%-24s %-38s %-10s %-8s %s"
            % (p.name[:24], p.uuid, p.key_mgmt, p.autoconnect, p.iface)
        )
    if store:
        store.close_all()
    return 0


def cmd_doctor(args):
    cfg, log, backend, store = _build(args)
    checks = []
    try:
        checks = list(backend.self_test())
    except Exception as exc:
        checks.append(("backend self_test", False, str(exc)))
    if store:
        try:
            checks.append(("数据库", True, "%s (%d 字节)" % (store.path, store.db_size_bytes())))
        except Exception as exc:
            checks.append(("数据库", False, str(exc)))
    keyfiles = (cfg.get("wifi", {}).get("connect") or {}).get("keyfiles_dir")
    checks.append(("keyfiles 目录", os.path.isdir(keyfiles or ""), keyfiles))
    checks.append(("配置档", True, getattr(args, "config", None) or "(内置默认)"))
    checks.append(("后端", True, backend.NAME))

    fails = 0
    if args.json:
        print(json.dumps({"ok": True, "data": {
            "checks": [{"name": n, "ok": bool(o), "detail": str(d)} for n, o, d in checks]
        }}, ensure_ascii=False, indent=2))
    else:
        for name, ok, detail in checks:
            flag = "OK  " if ok else "FAIL"
            if not ok:
                fails += 1
            print("[%s] %-28s %s" % (flag, name, detail))
    if store:
        store.close_all()
    return 1 if fails else 0


def cmd_selftest(args):
    """跑离线单元测试（不需要 nmcli / Linux / root）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tests_dir = os.path.join(root, "tests")
    if not os.path.isdir(tests_dir):
        print("找不到 tests 目录: %s" % tests_dir)
        return 2
    import unittest

    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_*.py", top_level_dir=root)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def cmd_probe_sae(args):
    """探测 SAE 支持。分两层：配置层（零风险）与真实握手（会占用 wlan0）。"""
    cfg, log, backend, store = _build(args)
    caps = backend.capabilities()
    print("后端: %s" % caps.name)
    print("SAE 配置层可写: %s" % caps.sae_configurable)
    for e in caps.sae_evidence:
        print("  证据: %s" % e)
    if hasattr(backend, "verify_sae_handshake"):
        if args.handshake:
            print("\n正在做真实握手验证（会短暂占用 wlan0）...")
            ok, detail = backend.verify_sae_handshake(
                ssid=args.ssid, bssid=args.bssid, password=args.password, timeout=args.timeout
            )
            print("握手可用: %s" % ok)
            for d in detail:
                print("  %s" % d)
        else:
            print("\n（加 --handshake 做真实握手验证）")
    if store:
        store.close_all()
    return 0


def cmd_install_hint(args):
    print(__doc__)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="wifimgr", description="WiFi Manager %s" % __version__)
    p.add_argument("--config", help="配置文件路径（默认 /etc/wifimgr.json，不存在则用内置默认）")
    p.add_argument("--backend", choices=["auto", "nmcli", "wpasupplicant", "fake"], help="强制后端")
    p.add_argument("--no-syslog", action="store_true", help="不写 syslog（调试用）")
    p.add_argument("--version", action="version", version="wifimgr " + __version__)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="启动 HTTP 服务")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("scan", help="扫描周围 WiFi")
    s.add_argument("--cached", action="store_true", help="不强制触发 rescan")
    s.add_argument("--json", action="store_true", help="输出 JSON")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("status", help="查看当前连接状态")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("connect", help="连接网络")
    s.add_argument("--ssid", required=True)
    s.add_argument("--bssid", default="")
    s.add_argument("--password", help="直接在命令行给密码（会出现在 ps，慎用）")
    s.add_argument("--ask-pass", action="store_true", help="从 stdin 读密码（推荐）")
    s.add_argument("--auth-kind", default="psk", choices=["open", "psk", "sae", "mixed", "wep"])
    s.add_argument("--sae-policy", default="psk_first", choices=["psk_first", "force_psk", "force_sae"])
    s.add_argument("--bssid-lock", action="store_true")
    s.add_argument("--no-remember", action="store_true")
    s.set_defaults(func=cmd_connect)

    s = sub.add_parser("profiles", help="列出 NM profile")
    s.set_defaults(func=cmd_profiles)

    s = sub.add_parser("doctor", help="环境自检")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("selftest", help="跑离线单元测试")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("probe-sae", help="探测 SAE 支持")
    s.add_argument("--handshake", action="store_true", help="做真实握手验证（会占用 wlan0）")
    s.add_argument("--ssid", default="")
    s.add_argument("--bssid", default="")
    s.add_argument("--password", default="")
    s.add_argument("--timeout", type=int, default=45)
    s.set_defaults(func=cmd_probe_sae)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except AppError as exc:
        print(
            json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False, indent=2),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
