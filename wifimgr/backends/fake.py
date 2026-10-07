"""FakeBackend —— 回放真实 nmcli 输出，让逻辑能在无 nmcli 的机器上测试。

数据源是 NAS 上实测抓取的真实输出（含转义 BSSID、中文 SSID、空 SSID 隐藏网络、
缺失字段等真实边界），固化为 ``tests/fixtures/*.txt``。

它同时承担一条**安全不变量**的验证：记录所有 argv，测试断言密码
从不出现其中。这把「密码不进 argv」从设计意图变成可执行检查。
"""

import io
import os

from ..errors import AppError
from ..models import (
    AUTH_OPEN,
    AUTH_PSK,
    AUTH_SAE,
    PHASE_ACTIVATED,
    PHASE_HANDSHAKE_FAILED,
    PHASE_REJECTED,
    PHASE_TIMEOUT,
    Capabilities,
    ConnStatus,
    ConnectRequest,
    ConnectResult,
    ProfileInfo,
    ScanEntry,
)
from ..terse import normalize_bssid, parse_terse_lines
from .base import Backend, parse_iw_link, security_from_flags, signal_to_int

_FIXTURE_DIR = None


def set_fixture_dir(path):
    global _FIXTURE_DIR
    _FIXTURE_DIR = path


def _fixture(name, default=""):
    if not _FIXTURE_DIR:
        return default
    path = os.path.join(_FIXTURE_DIR, name)
    if not os.path.isfile(path):
        return default
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


class FakeBackend(Backend):
    """回放式后端。

    scenario 可选：
      idle / connected / wrong_password / ap_gone / wlan0_busy /
      scan_rate_limited / sae_handshake_fail
    """

    NAME = "fake"

    SCAN_FIELDS = ["DEVICE", "SSID", "BSSID", "FREQ", "SIGNAL", "SECURITY"]
    # fixture scan_rich.txt 是 `-f DEVICE,SSID,BSSID,SIGNAL,WPA-FLAGS,RSN-FLAGS,IN-USE`
    # 的真实输出，**首列是 DEVICE**，所以字段表必须与之对齐，否则 BSSID 会被
    # 解析成 'wlan0' 导致 flags 关联全部落空。
    FLAG_FIELDS = ["DEVICE", "SSID", "BSSID", "SIGNAL", "WPA-FLAGS", "RSN-FLAGS", "IN-USE"]
    ACTIVE_FIELDS = ["NAME", "UUID", "TYPE", "DEVICE"]

    def __init__(self, cfg, log, scenario="idle", ifname="wlan0"):
        Backend.__init__(self, cfg, log)
        self.ifname = ifname
        self.scenario = scenario
        self.calls = []  # 所有 argv 元组，供测试断言
        self._store = None
        self._profiles = {
            "RD08_IoT": {
                "uuid": "188621c0-8c23-4998-bced-556353f06c53",
                "ssid": "RD08_IoT",
                "key_mgmt": "wpa-psk",
            }
        }
        self._active = None
        self._ip = ""
        self._signal = -16

    def set_busy_lock(self, lock):
        self._busy = lock

    def set_store(self, store):
        self._store = store

    def available(self):
        return True

    @classmethod
    def probe(cls, cfg):
        return Capabilities(
            "fake",
            can_scan=True,
            can_connect=True,
            sae_configurable=True,
            sae_handshake_verified=False,  # 与实机结论一致
            sae_evidence=["fixture:配置层接受 sae，握手未验证"],
            notes=["这是 FakeBackend，仅用于测试"],
        )

    # ---------- 扫描 ----------
    def scan(self, force=True):
        self.calls.append(("dev", "wifi", "list", "ifname", self.ifname))
        if self.scenario == "scan_rate_limited":
            raise AppError(
                "RATE_LIMITED",
                "扫描过于频繁，NetworkManager 拒绝",
                detail={"nmcli": "Error: Scan not allowed while already running"},
                retryable=True,
            )
        if self.scenario == "wlan0_busy":
            raise AppError("BUSY", "设备忙", retryable=True)

        rows = parse_terse_lines(_fixture("scan_wlan0.txt"), self.SCAN_FIELDS)
        flags = {}
        for row in parse_terse_lines(_fixture("scan_rich.txt"), self.FLAG_FIELDS):
            flags[normalize_bssid(row.get("BSSID", ""))] = row

        entries = []
        for row in rows:
            bssid = normalize_bssid(row.get("BSSID", ""))
            sec = row.get("SECURITY", "")
            auth = None
            in_use = False
            wpa_flags = ""
            rsn_flags = ""
            if bssid in flags:
                fr = flags[bssid]
                wpa_flags = fr.get("WPA-FLAGS", "")
                rsn_flags = fr.get("RSN-FLAGS", "")
                sec, auth = security_from_flags(sec, wpa_flags, rsn_flags)
                in_use = (fr.get("IN-USE", "").strip() == "*")
            e = ScanEntry(
                ssid=row.get("SSID", ""),
                bssid=bssid,
                signal=signal_to_int(row.get("SIGNAL")),
                freq=row.get("FREQ", ""),
                security=sec,
                auth_kind=auth or "unknown",
                wpa_flags=wpa_flags,
                rsn_flags=rsn_flags,
                in_use=in_use,
                iface=self.ifname,
            )
            entries.append(e)

        if self.scenario == "connected":
            for e in entries:
                if e.ssid == "密码是八个八wifi5":
                    e.in_use = True
        entries.sort(key=lambda e: (e.signal is None, -(e.signal or -999)))
        return entries

    # ---------- 状态 ----------
    def status(self):
        if self.scenario == "connected" or self._active:
            return ConnStatus(
                connected=True,
                source="nm_active",
                confidence=1.0,
                ssid=self._active or "密码是八个八wifi5",
                bssid="62:4F:3B:18:31:9B",
                profile_name=self._active or "密码是八个八wifi5",
                iface=self.ifname,
                ip=self._ip or "192.168.31.64",
                signal=self._signal,
                state="connected",
                checked_at=0.0,
            )
        return ConnStatus(
            connected=False,
            source="none",
            confidence=0.0,
            iface=self.ifname,
            state="disconnected",
            checked_at=0.0,
        )

    def is_busy_activating(self):
        return False

    # ---------- profile ----------
    def list_profiles(self):
        return [
            ProfileInfo(
                name=n,
                uuid=p["uuid"],
                type="802-11-wireless",
                iface=self.ifname,
                autoconnect=True,
                key_mgmt=p["key_mgmt"],
                has_secret=True,
            )
            for n, p in self._profiles.items()
        ]

    def profile_exists(self, name):
        return name in self._profiles

    def delete_profile(self, name):
        return self._profiles.pop(name, None) is not None

    # ---------- 连接 ----------
    def apply_profile(self, profile_name, ssid, password=None, key_mgmt="wpa-psk",
                      bssid=None, remember=True, bssid_lock=False, store=None, extra=None):
        """模拟写 keyfile。**密码不进 argv**（这里根本没有 argv）。"""
        from .. import nmkey

        body = nmkey.render_keyfile(
            profile_name=profile_name,
            ssid=ssid,
            password=password,
            key_mgmt=key_mgmt,
            bssid=bssid if (bssid and bssid_lock) else None,
            iface=self.ifname,
        )
        self.calls.append(("connection", "reload"))
        self._profiles[profile_name] = {
            "uuid": nmkey.stable_uuid(profile_name),
            "ssid": ssid,
            "key_mgmt": key_mgmt,
            "body": body,
        }
        if store is not None:
            # 与真实 NMBackend.apply_profile 保持一致：登记 managed，
            # 否则 delete_network 的「只删本应用创建的」保护会永远拒绝。
            store.upsert_profile_ref(
                profile_name,
                uuid=self._profiles[profile_name]["uuid"],
                managed=True,
                key_mgmt=key_mgmt,
                has_psk=bool(password),
            )
            store.upsert_saved_network(
                profile_name=profile_name,
                ssid=ssid,
                security=key_mgmt,
                key_mgmt=key_mgmt,
                iface=self.ifname,
            )
        return {"uuid": self._profiles[profile_name]["uuid"], "changed": True, "action": "created"}

    def activate_profile(self, profile_name, timeout=None):
        self.calls.append(("connection", "up", profile_name))
        if self.scenario == "wrong_password":
            return ConnectResult(
                ok=False,
                phase=PHASE_HANDSHAKE_FAILED,
                message="配置已写入并激活，但未获取到 IP。最可能原因：密码错误。",
                profile_name=profile_name,
            )
        if self.scenario == "ap_gone":
            return ConnectResult(
                ok=False,
                phase=PHASE_HANDSHAKE_FAILED,
                message="扫描时该 AP 存在，连接时找不到。",
                profile_name=profile_name,
            )
        if self.scenario == "sae_handshake_fail":
            return ConnectResult(
                ok=False,
                phase=PHASE_HANDSHAKE_FAILED,
                message="配置已写入并激活，但未获取到 IP（SAE 握手在本机失败）。",
                profile_name=profile_name,
            )
        if self.scenario == "wlan0_busy":
            return ConnectResult(ok=False, phase="busy", message="设备忙")
        prof = self._profiles.get(profile_name, {})
        self._active = prof.get("ssid", profile_name)
        self._ip = "192.168.31.64"
        return ConnectResult(
            ok=True,
            phase=PHASE_ACTIVATED,
            message="已连接 %s" % self._active,
            profile_name=profile_name,
            ssid=self._active,
            ip=self._ip,
        )

    def connect(self, req):
        req.validate()
        if self.scenario == "ap_gone":
            return ConnectResult(
                ok=False,
                phase=PHASE_HANDSHAKE_FAILED,
                message="扫描时该 AP 存在，连接时找不到。建议重新扫描。",
                ssid=req.ssid,
                bssid=req.bssid,
            )
        km = "sae" if req.auth_kind == AUTH_SAE else "wpa-psk"
        if req.auth_kind == AUTH_OPEN:
            km = "none"
        name = req.profile_name or req.ssid
        self.apply_profile(name, req.ssid, req.password, km, req.bssid, req.remember, req.bssid_lock)
        res = self.activate_profile(name, timeout=req.timeout)
        res.requested_key_mgmt = km
        res.used_key_mgmt = km
        res.ssid = req.ssid
        res.bssid = req.bssid
        if res.ok and req.remember and self._store is not None:
            self._store.upsert_saved_network(
                profile_name=name,
                ssid=req.ssid,
                security=km,
                key_mgmt=km,
                iface=self.ifname,
            )
            self._store.record_connect_result(name, True, PHASE_ACTIVATED)
        return res

    def disconnect(self):
        self.calls.append(("device", "disconnect", self.ifname))
        self._active = None
        self._ip = ""
        return ConnectResult(ok=True, phase=PHASE_ACTIVATED, message="已断开")

    # ---------- 健康 ----------
    def self_test(self):
        return [
            ("fake backend", True, "scenario=%s" % self.scenario),
            ("fixtures 已加载", bool(_fixture("scan_wlan0.txt")), "scan_wlan0.txt"),
        ]
