"""NetworkManager 后端（主力）。

实测约束（NAS 192.168.31.47 / NM 1.22.10），全部已在代码里规避：

* D1 ``nmcli connection load`` 假成功 → 只用「写 keyfiles 目录 + con reload」，
    且**回读校验**。
* D2 keyfile ``type=wifi``（不是 802-11-wireless）。
* D3 keyfile ``bssid`` 用分号十进制。
* D4 SAE 配置层可写但**握手必失败** → ``Capabilities`` 区分
    ``sae_configurable`` 与 ``sae_handshake_verified``；默认 psk 优先。
* D5 ``-g`` 多字段 rc=2；``-t`` 对 ``dev show`` 输出为空 → ``dev show``
    一律 ``-f`` 不加 ``-t``；``-t`` 只用于 con show / dev wifi list / dev status。
* ``p2p0`` 会让 ``dev wifi list`` 结果翻倍 → 所有扫描强制 ``ifname wlan0``。
* ``WIFI-SIGNAL`` 在本驱动下恒空 → 信号强度取 ``iw dev wlan0 link``。
"""

import os
import re
import time

from .. import nmkey
from ..errors import AppError, ValidationError
from ..models import (
    AUTH_MIXED,
    AUTH_OPEN,
    AUTH_PSK,
    AUTH_SAE,
    AUTH_WEP,
    PHASE_ACTIVATED,
    PHASE_BUSY,
    PHASE_HANDSHAKE_FAILED,
    PHASE_REJECTED,
    PHASE_SKIPPED,
    PHASE_TIMEOUT,
    Capabilities,
    ConnStatus,
    ConnectRequest,
    ConnectResult,
    ProfileInfo,
    ScanEntry,
)
from ..runner import CONNECT_TIMEOUT, SCAN_TIMEOUT, which, run
from ..terse import normalize_bssid, parse_dev_show, parse_terse_lines, unescape_dev_show_value
from .base import (
    NM_BUSY_STATES,
    Backend,
    parse_iw_link,
    security_from_flags,
    signal_to_int,
)

# dev wifi list 的字段。注意 -t 对它有效（与 dev show 不同）。
SCAN_FIELDS = ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"]
SCAN_FLAG_FIELDS = ["BSSID", "WPA-FLAGS", "RSN-FLAGS", "IN-USE"]
ACTIVE_FIELDS = ["NAME", "UUID", "TYPE", "DEVICE"]

# 错误分类关键词表 —— 用 nmcli 退出码 + stderr 关键词，不解析人类提示做主要判断。
NM_AUTH_HINTS = (
    "pre-shared key may be incorrect",
    "no secrets provided",
    "4-way handshake",
    "reason=16",
    "reason=17",
    "reason=23",
    "authentication required",
    "invalid password",
    "eap-failed",
    "eapol",
    "sae",
)
NM_CONFIG_HINTS = (
    "unknown connection",
    "invalid setting",
    "invalid keyfile",
    "no settings plugin",
    "not a valid",
    "unsupported",
    "missing property",
    "cannot be set",
    "connection is not available",
)
NM_BUSY_HINTS = (
    "already active",
    "activation in progress",
    "scan not allowed",
    "device busy",
    "in-progress",
    "not allowed while already running",
)
NM_GONE_HINTS = (
    "network could not be found",
    "no network with ssid",
    "ssid-not-found",
    "not found",
)

STATE_RE = re.compile(r"^(\d+)\s*\(([^)]*)\)")


def _state_from_raw(raw):
    """``100 (connected)`` -> ``("connected", 100)``。"""
    if not raw:
        return "", None
    m = STATE_RE.match(raw.strip())
    if not m:
        return raw.strip(), None
    return m.group(2).strip(), int(m.group(1))


class NMBackend(Backend):
    NAME = "nmcli"

    def __init__(self, cfg, log, nmcli=None, ifname=None, keyfiles_dir=None):
        Backend.__init__(self, cfg, log)
        self.nmcli = nmcli or which("nmcli")
        self.ifname = ifname or (cfg.get("wifi", {}) or {}).get("ifname", "wlan0")
        connect_cfg = (cfg.get("wifi", {}) or {}).get("connect", {}) or {}
        self.keyfiles_dir = keyfiles_dir or connect_cfg.get("keyfiles_dir") or nmkey.KEYFILE_DIR
        self.snapshot_dir = connect_cfg.get("snapshot_dir") or ""
        self.snapshot_keep = int(connect_cfg.get("snapshot_keep") or 20)
        self._busy = None  # 由 set_busy_lock 注入
        # 由 set_store 注入。_store_remember / apply_profile 依赖它把
        # 「已保存网络」写进数据库；为 None 时会静默跳过，导致 UI 上
        # 「已保存的网络」永远是空的。
        self.store = None

    def set_busy_lock(self, lock):
        self._busy = lock

    def set_store(self, store):
        """注入 Store。由 __main__ 在启动时调用。"""
        self.store = store

    # ---------- 可用性 ----------
    def available(self):
        return bool(self.nmcli) and os.path.isfile(self.nmcli or "")

    @classmethod
    def probe(cls, cfg):
        exe = which("nmcli")
        if not exe:
            return None
        r = run([exe, "--version"], timeout=10)
        if not r.ok:
            return None
        ver = (r.stdout or "").strip()
        caps = Capabilities("nmcli", can_scan=True, can_connect=True)
        caps.notes.append("nmcli version: %s" % ver)

        # SA-E1: supplicant 二进制里是否有 SAE 符号
        sae_evidence = []
        ws = which("wpa_supplicant", ("/usr/sbin/wpa_supplicant", "/sbin/wpa_supplicant"))
        sae_symbols = 0
        if ws:
            try:
                with open(ws, "rb") as fh:
                    blob = fh.read()
                sae_symbols = blob.count(b"SAE")
                sae_evidence.append("S1 wpa_supplicant 存在, SAE 符号 %d 个" % sae_symbols)
            except OSError as exc:
                sae_evidence.append("S1 wpa_supplicant 读取失败: %s" % exc)
        else:
            sae_evidence.append("S1 未找到 wpa_supplicant")
        caps.sae_evidence = sae_evidence
        # 注意：这里只标「配置层可能支持」。真实握手能力由 verify_sae_handshake()
        # 实测得出，不靠 grep 猜（D4 的教训）。

        # 权限（root 下应全 yes）
        try:
            pr = run([exe, "general", "permissions"], timeout=10)
            if pr.ok:
                for line in (pr.stdout or "").splitlines():
                    if "wifi.scan" in line:
                        caps.notes.append(line.strip())
        except Exception:
            pass

        # iw 是否可用（信号强度只能从它取）
        if which("iw"):
            caps.notes.append("iw 可用：信号强度取自 iw dev <if> link")
        else:
            caps.notes.append("iw 不可用：信号强度将无法显示（nmcli WIFI-SIGNAL 在本驱动下恒空）")
        return caps

    def verify_sae_handshake(self, ssid=None, bssid=None, password=None, timeout=45):
        """**实测** SAE 握手是否真的可用。

        与 :meth:`probe` 的配置层判断不同，这里会真的建一个临时 profile 并连接。
        默认用「保证不存在的 BSSID」只做配置层验证（零风险）；
        传入真实 ssid/bssid/password 时做完整握手验证（会短暂占用 wlan0）。

        实测结论（2026-10-08，rtl8188fu + wpa_supplicant 2.9 + 内核 4.4.35_ecoo）：
        配置层 ``key-mgmt=sae`` 可写入且回读正确，但真实握手必然
        ``ssid-not-found`` 超时。所以 ``sae_handshake_verified`` 默认 False。
        """
        probe_name = "wifimgr-saeprobe-tmp"
        created = False
        try:
            # 配置层探测需要一个**合法的** WPA 口令（8–63 字节），但它只是
            # 拿去让 NM 接受这个 profile —— 绝不能用真实网络密码，更不能硬编码。
            # 这里用一个固定的无害占位口令；真实握手验证时由调用方传入。
            probe_password = password or "wifimgr-probe-placeholder"
            body = nmkey.render_keyfile(
                profile_name=probe_name,
                ssid=ssid or "wifimgr-saeprobe",
                password=probe_password,
                key_mgmt="sae",
                bssid=bssid,
                iface=self.ifname,
                autoconnect=False,
            )
            path = nmkey.keyfile_path(self.keyfiles_dir, probe_name)
            nmkey.write_keyfile(path, body)
            self._reload()
            created = True
            # 回读：确认 NM 真的读到了 sae（不信任任何 rc）
            km = self._get_field(probe_name, "802-11-wireless-security.key-mgmt")
            if km != "sae":
                return False, ["配置层不支持 sae（回读 %r）" % (km,)]
            if not ssid:
                # 只验证到配置层
                return False, ["配置层接受 sae（未做真实握手验证）"]
            res = self.activate_profile(probe_name, timeout=timeout)
            ok = res.ok
            detail = ["握手验证: phase=%s message=%s" % (res.phase, res.message)]
            return ok, detail
        except AppError as exc:
            return False, ["SAE 验证异常: %s" % exc]
        finally:
            if created:
                self.delete_profile(probe_name)

    # ---------- 底层调用 ----------
    def _nm(self, args, timeout=15, lock=False):
        """调用 nmcli。``lock=True`` 时持全局 busy 锁（写操作必须）。"""
        if lock and self._busy is not None:
            self._busy.acquire()
        try:
            return run([self.nmcli] + list(args), timeout=timeout)
        finally:
            if lock and self._busy is not None:
                self._busy.release()

    def _reload(self):
        """重载 keyfiles。这是 D1 的关键替代路径。"""
        return self._nm(["connection", "reload"], timeout=20, lock=True)

    def _get_field(self, profile, field):
        """``nmcli -g <field> con show <profile>`` —— **单字段**（D5）。"""
        r = self._nm(["-g", field, "connection", "show", profile], timeout=15)
        if not r.ok:
            return ""
        return unescape_dev_show_value((r.stdout or "").strip())

    # ---------- 扫描 ----------
    def scan(self, force=True):
        """扫描周围 AP。**强制 ifname**，否则 p2p0 会让结果翻倍。"""
        scan_cfg = (self.cfg.get("wifi", {}) or {}).get("scan", {}) or {}
        timeout = int(scan_cfg.get("command_timeout_sec") or SCAN_TIMEOUT)

        if force:
            # rescan 是阻塞调用（实测 2-5s），必须有超时保护
            self._nm(["device", "wifi", "rescan", "ifname", self.ifname], timeout=timeout)

        r = self._nm(
            ["-t", "-f", ",".join(SCAN_FIELDS), "dev", "wifi", "list", "ifname", self.ifname],
            timeout=timeout,
            lock=True,
        )
        if r.timed_out:
            raise AppError("NMCLI_TIMEOUT", "扫描超时（%ds）" % timeout, detail=r.to_dict())
        if not r.ok:
            stderr = (r.stderr or "").lower()
            if any(k in stderr for k in NM_BUSY_HINTS):
                raise AppError(
                    "BUSY",
                    "设备正忙，扫描被拒绝（NetworkManager 限速）",
                    detail=r.to_dict(),
                    retryable=True,
                )
            raise AppError("NMCLI_FAILED", "扫描失败", detail=r.to_dict())

        rows = parse_terse_lines(r.stdout, SCAN_FIELDS)
        entries = []
        phantom = 0
        for row in rows:
            dev = row.get("DEVICE", "")
            if dev and dev != self.ifname:
                # p2p0 混入 —— 丢弃并记一次
                continue
            bssid = normalize_bssid(row.get("BSSID", ""))
            if not bssid:
                # NM 会为「有 profile 但当前扫描不到」的 SSID 吐一行占位记录：
                #   wlan0:RD08_IoT::0 MHz:0:WPA1 WPA2
                # BSSID 为空 + 0 MHz + 信号 0。它不可连接（会 ssid-not-found），
                # 展示出来只会让用户点一个连不上的网络。丢弃并计数。
                #
                # 注意：真正的隐藏网络是 **SSID 为空但 BSSID 存在**，
                # 所以用 BSSID 判定是安全的，不会误伤隐藏网络。
                phantom += 1
                continue
            sec = row.get("SECURITY", "")
            entries.append(
                ScanEntry(
                    ssid=row.get("SSID", ""),
                    bssid=bssid,
                    signal=signal_to_int(row.get("SIGNAL")),
                    freq=row.get("FREQ", ""),
                    security=sec,
                    iface=self.ifname,
                )
            )
        if phantom:
            self.log.info(
                "backend",
                "scan.phantom",
                "已丢弃 %d 条无 BSSID 的占位记录（对应 profile 的 SSID 当前不在范围内）" % phantom,
                {"count": phantom},
            )

        # 第二次调用补精确加密标志（SECURITY 文本无法证明 SAE）
        self._merge_flags(entries, timeout)
        entries.sort(key=lambda e: (e.signal is None, -(e.signal or -999)))
        return entries

    def _merge_flags(self, entries, timeout):
        if not entries:
            return
        r = self._nm(
            ["-t", "-f", ",".join(SCAN_FLAG_FIELDS), "dev", "wifi", "list", "ifname", self.ifname],
            timeout=timeout,
        )
        if not r.ok:
            return
        by_bssid = {}
        for row in parse_terse_lines(r.stdout, SCAN_FLAG_FIELDS):
            b = normalize_bssid(row.get("BSSID", ""))
            if b:
                by_bssid[b] = row
        for e in entries:
            row = by_bssid.get(e.bssid)
            if not row:
                continue
            e.wpa_flags = row.get("WPA-FLAGS", "")
            e.rsn_flags = row.get("RSN-FLAGS", "")
            e.in_use = (row.get("IN-USE", "").strip() == "*")
            norm, auth = security_from_flags(e.security, e.wpa_flags, e.rsn_flags)
            e.security = norm
            e.auth_kind = auth

    # ---------- 状态（四级回退） ----------
    def status(self):
        detail = {}
        iface = self.ifname

        # tier 1: 活跃 profile（DEVICE 过滤，NAME 是 profile id 不是 SSID）
        profile_name = ""
        connected = False
        r = self._nm(["-t", "-f", ",".join(ACTIVE_FIELDS), "connection", "show", "--active"], timeout=15)
        if r.ok:
            for row in parse_terse_lines(r.stdout, ACTIVE_FIELDS):
                if row.get("DEVICE") == iface:
                    profile_name = row.get("NAME", "")
                    connected = True
                    detail["active_uuid"] = row.get("UUID", "")
                    break

        # tier 2: 设备状态（-f 不加 -t！D5）
        state = ""
        state_code = None
        r = self._nm(
            ["-f", "GENERAL.STATE", "dev", "show", iface],
            timeout=10,
        )
        if r.ok:
            parsed = parse_dev_show(r.stdout)
            state, state_code = _state_from_raw(parsed.get("GENERAL.STATE", ""))
        detail["state_raw"] = state
        if state_code == 100:
            connected = True

        # IP：-g 单字段
        ip = ""
        r = self._nm(["-g", "IP4.ADDRESS", "dev", "show", iface], timeout=10)
        if r.ok:
            first = (r.stdout or "").strip().splitlines()
            if first and first[0]:
                ip = first[0].split("/")[0]

        # tier 3: iw —— 取 SSID/BSSID/信号（nmcli 的 WIFI-SIGNAL 本驱动恒空）
        ssid = ""
        bssid = ""
        signal = None
        iw = which("iw")
        if iw:
            ri = run([iw, "dev", iface, "link"], timeout=10)
            if ri.ok:
                info = parse_iw_link(ri.stdout)
                if info["connected"]:
                    connected = True
                    ssid = info["ssid"]
                    bssid = normalize_bssid(info["bssid"])
                    signal = info["signal"]
                    detail["iw"] = "connected"
                else:
                    detail["iw"] = "not connected"

        # 判定来源与可信度
        if connected and profile_name:
            source, conf = "nm_active", 1.0
        elif connected and ssid:
            source, conf = "iw_link", 0.9
        elif connected and state_code == 100:
            source, conf = "nm_state", 0.8
        elif connected:
            source, conf = "weak", 0.4
        else:
            source, conf = "none", 0.0

        if not ssid and profile_name:
            # profile 名恰好等于 SSID 时才借用，否则不要误导用户
            p = self._get_field(profile_name, "802-11-wireless.ssid") if profile_name else ""
            if p:
                ssid = p
                detail["ssid_from"] = "profile"

        return ConnStatus(
            connected=connected,
            source=source,
            confidence=conf,
            ssid=ssid,
            bssid=bssid,
            profile_name=profile_name,
            iface=iface,
            ip=ip,
            signal=signal,
            state=state,
            checked_at=time.time(),
            detail=detail,
        )

    def is_busy_activating(self):
        """NM 是否正在 activating/deactivating —— 守护必须尊重。"""
        r = self._nm(["-f", "GENERAL.STATE", "dev", "show", self.ifname], timeout=10)
        if not r.ok:
            return False
        state, _ = _state_from_raw(parse_dev_show(r.stdout).get("GENERAL.STATE", ""))
        return state in NM_BUSY_STATES or "connecting" in state or "activating" in state

    # ---------- profile ----------
    def list_profiles(self):
        r = self._nm(["-t", "-f", "NAME,TYPE,AUTOCONNECT", "connection", "show"], timeout=15)
        if not r.ok:
            return []
        out = []
        for row in parse_terse_lines(r.stdout, ["NAME", "TYPE", "AUTOCONNECT"]):
            name = row.get("NAME", "")
            if not name:
                continue
            out.append(
                ProfileInfo(
                    name=name,
                    uuid=self._get_field(name, "connection.uuid"),
                    type=row.get("TYPE", ""),
                    iface=self._get_field(name, "connection.interface-name"),
                    autoconnect=(row.get("AUTOCONNECT", "").lower() == "yes"),
                    key_mgmt=self._get_field(name, "802-11-wireless-security.key-mgmt"),
                    has_secret=bool(self._get_field(name, "802-11-wireless-security.psk")),
                )
            )
        return out

    def profile_exists(self, name):
        return self._get_field(name, "connection.uuid") != ""

    def delete_profile(self, name):
        r = self._nm(["connection", "delete", name], timeout=20, lock=True)
        return r.ok

    # ---------- 连接 ----------
    def apply_profile(
        self,
        profile_name,
        ssid,
        password=None,
        key_mgmt="wpa-psk",
        bssid=None,
        remember=True,
        bssid_lock=False,
        store=None,
        extra=None,
    ):
        """写入 keyfile 并 reload，然后**回读校验**。

        这是密码唯一流向磁盘的入口。返回值 dict(uuid, changed, action)。
        """
        keyfiles_dir = self.keyfiles_dir
        if not os.path.isdir(keyfiles_dir):
            raise AppError(
                "KEYFILE_REJECTED",
                "keyfiles 目录不存在: %s" % keyfiles_dir,
                hint="检查 NetworkManager 是否安装在标准路径",
            )
        if bssid_lock and bssid:
            nmkey.snapshot_existing(
                keyfiles_dir, profile_name, self.snapshot_dir, self.snapshot_keep
            )
        elif self.snapshot_dir:
            # 即便不锁 BSSID，覆盖已有 profile 前也留一份快照
            nmkey.snapshot_existing(
                keyfiles_dir, profile_name, self.snapshot_dir, self.snapshot_keep
            )

        body = nmkey.render_keyfile(
            profile_name=profile_name,
            ssid=ssid,
            password=password,
            key_mgmt=key_mgmt,
            bssid=bssid if (bssid and bssid_lock) else None,
            iface=self.ifname,
            autoconnect=True,
            extra=extra,
        )
        path = nmkey.keyfile_path(keyfiles_dir, profile_name)
        existed = os.path.isfile(path)
        nmkey.write_keyfile(path, body)

        # D1: 不信任 reload 的 rc，靠回读确认
        self._reload()

        got_uuid = self._get_field(profile_name, "connection.uuid")
        if not got_uuid:
            raise nmkey.KeyfileRejected(
                "写入后 NM 未识别该 profile（reload 未生效或 plugin 不接受）",
                detail={"profile": profile_name, "path": path},
            )
        got_ssid = self._get_field(profile_name, "802-11-wireless.ssid")
        if got_ssid != ssid:
            raise nmkey.KeyfileRejected(
                "SSID 回读不一致：期望 %r 实际 %r" % (ssid, got_ssid),
                detail={"profile": profile_name},
            )
        got_km = self._get_field(profile_name, "802-11-wireless-security.key-mgmt")
        if got_km and got_km != key_mgmt:
            # 分级降级：去掉可选 key 再试一次（pmf 之类 NM 版本可能不认）
            if extra:
                body2 = nmkey.render_keyfile(
                    profile_name=profile_name,
                    ssid=ssid,
                    password=password,
                    key_mgmt=key_mgmt,
                    bssid=bssid if (bssid and bssid_lock) else None,
                    iface=self.ifname,
                    autoconnect=True,
                    extra=None,
                )
                nmkey.write_keyfile(path, body2)
                self._reload()
                got_km = self._get_field(profile_name, "802-11-wireless-security.key-mgmt")
        if got_km and got_km != key_mgmt:
            raise nmkey.KeyfileRejected(
                "key-mgmt 回读不一致：期望 %r 实际 %r" % (key_mgmt, got_km),
                detail={"profile": profile_name, "hint": "NM 版本可能不支持该 key-mgmt"},
            )
        if bssid and bssid_lock:
            got_bssid = normalize_bssid(self._get_field(profile_name, "802-11-wireless.bssid"))
            if got_bssid and got_bssid != normalize_bssid(bssid):
                raise nmkey.KeyfileRejected(
                    "BSSID 回读不一致：期望 %r 实际 %r" % (bssid, got_bssid),
                    detail={"profile": profile_name},
                )
        # 显式补一次 autoconnect，避免 reload 覆盖后丢字段
        self._nm(
            ["connection", "modify", profile_name, "connection.autoconnect", "yes"],
            timeout=15,
            lock=True,
        )
        if store is not None:
            store.upsert_profile_ref(
                profile_name,
                uuid=got_uuid,
                managed=True,
                key_mgmt=key_mgmt,
                # 注意参数名是 has_psk（只有布尔标记，不存密码本身）
                has_psk=bool(password),
            )
            store.upsert_saved_network(
                profile_name=profile_name,
                ssid=ssid,
                uuid=got_uuid,
                bssid_lock=bssid if bssid_lock else None,
                security=key_mgmt,
                key_mgmt=key_mgmt,
                iface=self.ifname,
            )
        return {"uuid": got_uuid, "changed": True, "action": "updated" if existed else "created"}

    def activate_profile(self, profile_name, timeout=None):
        """``nmcli connection up`` + settle 判定。

        关键：**密码错误时 nmcli 可能返回 rc=0**（profile 激活成功、
        认证在后台失败），所以必须 settle 后再查状态做二次判定。
        """
        cfg = (self.cfg.get("wifi", {}) or {}).get("connect", {}) or {}
        t = int(timeout or cfg.get("command_timeout_sec") or CONNECT_TIMEOUT)
        settle = int(cfg.get("settle_sec") or 8)
        started = time.time()
        r = self._nm(["connection", "up", profile_name], timeout=t, lock=True)
        elapsed = int((time.time() - started) * 1000)

        if r.timed_out:
            return ConnectResult(
                ok=False,
                phase=PHASE_TIMEOUT,
                message="连接超时（%ds）—— AP 可能太远、信号弱或密码错误" % t,
                detail=r.to_dict(),
                profile_name=profile_name,
                duration_ms=elapsed,
            )
        if not r.ok:
            phase, message = self._classify_failure(r)
            return ConnectResult(
                ok=False,
                phase=phase,
                message=message,
                detail=r.to_dict(),
                profile_name=profile_name,
                duration_ms=elapsed,
            )

        # settle 后二次判定
        time.sleep(settle)
        st = self.status()
        if st.connected and (st.ip or st.state.startswith("connected")):
            return ConnectResult(
                ok=True,
                phase=PHASE_ACTIVATED,
                message="已连接 %s" % (st.ssid or profile_name),
                profile_name=profile_name,
                ssid=st.ssid,
                bssid=st.bssid,
                ip=st.ip,
                duration_ms=int((time.time() - started) * 1000),
            )
        return ConnectResult(
            ok=False,
            phase=PHASE_HANDSHAKE_FAILED,
            message=(
                "配置已写入并激活，但未获取到 IP。"
                "最可能原因：密码错误，或该 AP 的加密方式本机驱动不支持"
                "（WPA3/SAE 在本机实测握手失败）。"
            ),
            detail={"status": st.to_dict(), "nmcli": r.to_dict()},
            profile_name=profile_name,
            duration_ms=int((time.time() - started) * 1000),
        )

    def _classify_failure(self, r):
        err = (r.stderr or "") + " " + (r.stdout or "")
        low = err.lower()
        detail = r.to_dict()
        if any(k in low for k in NM_BUSY_HINTS):
            return PHASE_BUSY, "设备忙（NetworkManager 正在处理其它操作）"
        if any(k in low for k in NM_CONFIG_HINTS):
            return PHASE_REJECTED, (
                "NetworkManager 拒绝了配置：%s。这是应用/版本兼容问题，不是密码问题。"
                % ((r.stderr or "").strip()[:300])
            )
        if "ssid-not-found" in low or "network could not be found" in low:
            return PHASE_HANDSHAKE_FAILED, (
                "扫描时该 AP 存在，连接时找不到。可能是 AP 关闭/换信道，"
                "或 BSSID 绑定不匹配。建议重新扫描。"
            )
        if any(k in low for k in NM_AUTH_HINTS):
            return PHASE_HANDSHAKE_FAILED, "认证失败：密码错误，或加密方式不被本机驱动支持"
        return PHASE_REJECTED, ((r.stderr or "").strip()[:300] or "连接失败")

    def disconnect(self):
        r = self._nm(["device", "disconnect", self.ifname], timeout=30, lock=True)
        return ConnectResult(
            ok=r.ok,
            phase=PHASE_ACTIVATED if r.ok else PHASE_REJECTED,
            message="已断开" if r.ok else "断开失败",
            detail=r.to_dict(),
        )

    def connect(self, req):
        """带 key-mgmt 降级链的连接。

        因 D4，``psk_first`` 是默认策略：WPA2/WPA3 混合 AP 用 wpa-psk 即可
        协商成功（实测已连上），而 SAE 在本机必然握手失败。
        """
        from .. import nmkey as _nmkey  # noqa: F401  (保持显式依赖)

        req.validate()
        policy = req.sae_policy
        caps = None
        try:
            caps = self.capabilities()
        except Exception:
            pass

        order = []
        if req.auth_kind == AUTH_OPEN:
            order = ["none"]
        elif policy == "force_psk":
            order = ["wpa-psk"]
        elif policy == "force_sae":
            order = ["sae"]
        else:  # psk_first
            if req.auth_kind == AUTH_SAE:
                # 纯 WPA3-only：psk 也没用，但先试 psk 成本低
                order = ["wpa-psk", "sae"]
            elif req.auth_kind == AUTH_MIXED:
                # 混合 AP：psk 是实测可行路径，SAE 放后面兜底
                order = ["wpa-psk", "sae"]
            else:
                order = ["wpa-psk"]

        profile_name = req.profile_name or self._profile_name_for(req.ssid, req.bssid)
        attempts = []
        started = time.time()

        for km in order:
            if km == "sae" and caps is not None and not caps.sae_configurable:
                attempts.append(
                    {"key_mgmt": km, "phase": PHASE_SKIPPED, "error": "SAE_UNSUPPORTED"}
                )
                continue
            try:
                # 传 store 下去，让 apply_profile 同时写 profile_ref + saved_network；
                # 否则 remember=True 只会写 NM keyfile，本地列表没有记录。
                applied = self.apply_profile(
                    profile_name=profile_name,
                    ssid=req.ssid,
                    password=req.password,
                    key_mgmt=km,
                    bssid=req.bssid,
                    remember=req.remember,
                    bssid_lock=req.bssid_lock,
                    store=self.store if req.remember else None,
                )
            except AppError as exc:
                attempts.append(
                    {
                        "key_mgmt": km,
                        "phase": PHASE_REJECTED,
                        "error": exc.code,
                        "message": exc.message,
                    }
                )
                break  # 配置层被拒，换 km 也没用
            res = self.activate_profile(profile_name, timeout=req.timeout)
            res.requested_key_mgmt = km
            res.used_key_mgmt = km
            res.ssid = req.ssid
            res.bssid = req.bssid
            attempts.append(res.to_dict())
            if res.ok:
                if req.remember:
                    try:
                        if not self._store_remember(req, profile_name, km):
                            # 记录失败要让用户知道，否则「已勾选保存但列表为空」无从排查
                            res.detail["remember_warning"] = (
                                "网络已连接，但未能保存到列表（Store 不可用）"
                            )
                    except Exception as exc:
                        self.log.error(
                            "backend", "remember.failed", "记住网络失败", {"err": str(exc)}
                        )
                        res.detail["remember_warning"] = "网络已连接，但保存到列表时出错: %s" % exc
                return res
            if res.phase == PHASE_REJECTED:
                break
            if res.phase == PHASE_HANDSHAKE_FAILED and km == "sae":
                # D4: SAE 握手在本机必然失败，立刻降级，不要让用户等第二次超时
                attempts[-1]["note"] = (
                    "SAE 在本机实测握手失败（驱动/内核不支持），已自动降级"
                )

        final = attempts[-1] if attempts else {}
        phase = final.get("phase", PHASE_REJECTED)
        return ConnectResult(
            ok=False,
            phase=phase,
            message=self._explain(attempts),
            detail={"attempts": attempts},
            ssid=req.ssid,
            bssid=req.bssid,
            profile_name=profile_name,
            requested_key_mgmt=order[0] if order else None,
            used_key_mgmt=final.get("key_mgmt"),
            duration_ms=int((time.time() - started) * 1000),
            attempts=attempts,
        )

    def _store_remember(self, req, profile_name, key_mgmt):
        """记入本地配置（**不含密码**，密码已在 NM keyfile 里）。"""
        store = self.store
        if store is None:
            # 静默跳过会让「已保存的网络」永远为空且没有任何线索，
            # 这正是本次排查花时间的原因 —— 必须留下痕迹。
            self.log.error(
                "backend",
                "remember.no_store",
                "无法记录已保存网络：Store 未注入",
                {"profile": profile_name, "ssid": req.ssid},
            )
            return False
        store.upsert_saved_network(
            profile_name=profile_name,
            ssid=req.ssid,
            uuid=nmkey.stable_uuid(profile_name),
            bssid_lock=req.bssid if req.bssid_lock else None,
            security=key_mgmt,
            key_mgmt=key_mgmt,
            iface=req.iface,
        )
        store.record_connect_result(profile_name, True, PHASE_ACTIVATED)
        return True

    def _profile_name_for(self, ssid, bssid=None):
        """由 SSID 生成 profile 名。SSID 可能含中文/空格，均可用。"""
        name = ssid
        if bssid:
            name = "%s-%s" % (ssid, bssid.replace(":", "")[-6:])
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_. ").strip()
        return safe or "wifimgr-%d" % int(time.time())

    def _explain(self, attempts):
        """生成人能看懂的原因说明，**明确区分密码问题与能力问题**。"""
        if not attempts:
            return "没有任何尝试"
        notes = []
        for a in attempts:
            km = a.get("key_mgmt")
            ph = a.get("phase")
            if ph == PHASE_SKIPPED:
                notes.append("%s：跳过（%s）" % (km, a.get("error")))
            elif ph == PHASE_ACTIVATED:
                notes.append("%s：成功" % km)
            elif a.get("error") == "KEYFILE_REJECTED":
                notes.append("%s：配置被 NM 拒绝 —— 这是兼容问题，不是密码问题" % km)
            else:
                notes.append("%s：%s —— %s" % (km, ph, a.get("message") or a.get("note") or ""))
        tried = [a for a in attempts if a.get("phase") != PHASE_SKIPPED]
        all_handshake = bool(tried) and all(
            a.get("phase") == PHASE_HANDSHAKE_FAILED for a in tried
        )
        head = "；".join(notes)
        if all_handshake and any(a.get("key_mgmt") == "sae" for a in tried):
            return (
                "%s。SAE(WPA3) 在本机实测无法完成握手（rtl8188fu 驱动 + 内核 4.4 限制），"
                "已自动改用 WPA2；密码错误也会表现为同样的症状，请先核对密码。" % head
            )
        if all_handshake:
            return "%s。配置已成功写入，但认证握手未完成 —— 最可能是密码错误。" % head
        return head

    # ---------- 健康 ----------
    def self_test(self):
        checks = []
        checks.append(("nmcli 可执行", self.available(), self.nmcli or "未找到"))
        r = self._nm(["--version"], timeout=10)
        checks.append(("nmcli 可运行", r.ok, (r.stdout or "").strip() or (r.stderr or "").strip()))
        r = self._nm(["general", "status"], timeout=10)
        checks.append(("NetworkManager 运行中", r.ok, (r.stdout or "").strip()[:120]))
        rs = self._nm(["-t", "-f", "DEVICE,STATE", "dev", "status"], timeout=10)
        rows_status = parse_terse_lines(rs.stdout, ["DEVICE", "STATE"])
        row = None
        for r in rows_status:
            if r.get("DEVICE") == self.ifname:
                row = r
                break
        checks.append(
            (
                "接口 %s 存在" % self.ifname,
                row is not None,
                ("状态: %s" % row.get("STATE")) if row else "dev status 中未找到该设备",
            )
        )
        if row is not None:
            checks.append(
                (
                    "接口 %s 被 NetworkManager 管理" % self.ifname,
                    True,
                    "STATE=%s" % row.get("STATE"),
                )
            )
        rd = self._nm(["-f", "GENERAL.STATE", "dev", "show", self.ifname], timeout=10)
        state, _ = _state_from_raw(parse_dev_show(rd.stdout).get("GENERAL.STATE", ""))
        checks.append(("接口 %s 状态" % self.ifname, True, state or "未知"))
        checks.append(
            (
                "iw 可用（信号强度来源）",
                bool(which("iw")),
                which("iw") or "未安装：信号强度无法显示",
            )
        )
        rsc = self._nm(
            ["-t", "-f", ",".join(SCAN_FIELDS), "dev", "wifi", "list", "ifname", self.ifname],
            timeout=20,
        )
        srows = parse_terse_lines(rsc.stdout, SCAN_FIELDS) if rsc.ok else []
        real = [x for x in srows if normalize_bssid(x.get("BSSID", ""))]
        phantom_n = len(srows) - len(real)
        checks.append(
            (
                "扫描可用",
                rsc.ok,
                "返回 %d 个可见网络%s"
                % (
                    len(real),
                    ("（另有 %d 条无 BSSID 占位记录已忽略）" % phantom_n) if phantom_n else "",
                )
                if rsc.ok
                else ((rsc.stderr or "").strip()[:120] or "未知错误"),
            )
        )
        checks.append(
            (
                "keyfiles 目录",
                os.path.isdir(self.keyfiles_dir),
                self.keyfiles_dir,
            )
        )
        return checks
