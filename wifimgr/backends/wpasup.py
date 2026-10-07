"""wpa_supplicant 后端（给没有 NetworkManager 的 Linux，例如 OpenWrt）。

目标机有 NM，所以这条路径**未经实机验证** —— 它按 wpa_supplicant/iw 的标准接口实现，
用于满足「平台差异」这一交付要求，并在 FakeBackend 的对照测试下保证接口一致。

与 NM 后端的关键差异：
  * 扫描靠 ``iw dev <if> scan`` + ``iw dev <if> scan dump``（每次扫描前需先触发）
  * 连接靠 ``wpa_cli -i <if> reconfigure``（配置文件由本进程维护，不经过 NM）
  * 「已保存网络」直接就是 wpa_supplicant.conf 里的 block
"""

import os
import re
import time

from ..errors import AppError, BackendUnavailable
from ..models import (
    AUTH_OPEN,
    AUTH_PSK,
    AUTH_SAE,
    AUTH_WEP,
    PHASE_ACTIVATED,
    PHASE_HANDSHAKE_FAILED,
    PHASE_REJECTED,
    PHASE_TIMEOUT,
    Capabilities,
    ConnStatus,
    ConnectResult,
    ProfileInfo,
    ScanEntry,
)
from ..runner import SCAN_TIMEOUT, run, which
from ..terse import normalize_bssid
from .base import Backend, parse_iw_link, security_from_flags, signal_to_int

# iw scan dump: "BSS 62:4f:3b:18:31:9b(on wlan0) -- associated"
#                "    last seen: ... freq: 2412"
#                "    signal: -16.00 dBm"
#                "    SSID: 密码是八个八wifi5"
_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})", re.M)
_FREQ_RE = re.compile(r"^\s*freq:\s*(\d+(?:\.\d+)?)", re.M)
_SIGNAL_RE = re.compile(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)", re.M)
_SSID_RE = re.compile(r"^\s*SSID:\s*(.*)$", re.M)


class WpaSupplicantBackend(Backend):
    NAME = "wpasupplicant"

    def __init__(self, cfg, log, ifname=None, iw=None, wpa_cli=None):
        Backend.__init__(self, cfg, log)
        self.ifname = ifname or (cfg.get("wifi", {}) or {}).get("ifname", "wlan0")
        self.iw = iw or which("iw")
        self.wpa_cli = wpa_cli or which("wpa_cli", ("/usr/sbin/wpa_cli", "/sbin/wpa_cli"))
        self._busy = None

    def set_busy_lock(self, lock):
        self._busy = lock

    def available(self):
        return bool(self.iw) and bool(self.wpa_cli)

    @classmethod
    def probe(cls, cfg):
        iw = which("iw")
        wpa_cli = which("wpa_cli", ("/usr/sbin/wpa_cli", "/sbin/wpa_cli"))
        if not (iw and wpa_cli):
            return None
        caps = Capabilities("wpasupplicant", can_scan=True, can_connect=True)
        caps.notes.append("iw: %s" % iw)
        caps.notes.append("wpa_cli: %s" % wpa_cli)
        r = run([wpa_cli, "-v"], timeout=10)
        if r.ok:
            caps.notes.append((r.stdout or r.stderr or "").strip()[:80])
        return caps

    # ---------- 扫描 ----------
    def scan(self, force=True):
        if not self.available():
            raise BackendUnavailable("缺少 iw 或 wpa_cli")
        if force:
            # iw scan 需要先 up 起来，且是阻塞调用
            run([self.iw, "dev", self.ifname, "scan"], timeout=SCAN_TIMEOUT)
            time.sleep(1)
        r = run([self.iw, "dev", self.ifname, "scan", "dump"], timeout=SCAN_TIMEOUT)
        if not r.ok:
            raise AppError("NMCLI_FAILED", "iw scan dump 失败", detail=r.to_dict())
        entries = []
        blocks = _split_bss(r.stdout or "")
        for bssid, body in blocks:
            freq = None
            m = _FREQ_RE.search(body)
            if m:
                freq = int(float(m.group(1)))
            signal = None
            m = _SIGNAL_RE.search(body)
            if m:
                signal = int(round(float(m.group(1))))
            ssid = ""
            m = _SSID_RE.search(body)
            if m:
                from .base import decode_iw_ssid

                ssid = decode_iw_ssid(m.group(1).strip())
            sec, auth = self._security_from_iw(body)
            entries.append(
                ScanEntry(
                    ssid=ssid,
                    bssid=normalize_bssid(bssid),
                    signal=signal,
                    freq=str(freq) if freq else "",
                    security=sec,
                    auth_kind=auth,
                    iface=self.ifname,
                )
            )
        entries.sort(key=lambda e: (e.signal is None, -(e.signal or -999)))
        return entries

    def _security_from_iw(self, block):
        """从 iw 的 RSN/WPA 信息行推断加密方式。"""
        low = (block or "").lower()
        has_sae = "sae" in low
        has_psk = "psk" in low and "wpa" in low
        sec_text = ""
        if has_sae and not has_psk:
            sec_text = "WPA3"
        elif has_sae and has_psk:
            sec_text = "WPA2 WPA3"
        elif "wpa2" in low or has_psk:
            sec_text = "WPA2"
        elif "wpa1" in low:
            sec_text = "WPA1"
        return security_from_flags(sec_text, "", "")

    # ---------- 状态 ----------
    def status(self):
        ri = run([self.iw, "dev", self.ifname, "link"], timeout=10)
        info = parse_iw_link(ri.stdout if ri.ok else "")
        ip = ""
        rip = which("ip", ("/sbin/ip", "/usr/sbin/ip", "/bin/ip"))
        if rip:
            r = run([rip, "-4", "-o", "addr", "show", self.ifname], timeout=10)
            if r.ok:
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout or "")
                if m:
                    ip = m.group(1)
        connected = bool(info.get("connected"))
        return ConnStatus(
            connected=connected,
            source="iw_link" if connected else "none",
            confidence=0.9 if connected else 0.0,
            ssid=info.get("ssid", ""),
            bssid=normalize_bssid(info.get("bssid", "")),
            profile_name=info.get("ssid", ""),
            iface=self.ifname,
            ip=ip,
            signal=info.get("signal"),
            state="connected" if connected else "disconnected",
            checked_at=time.time(),
        )

    # ---------- 连接 ----------
    def _wpa_cli(self, args, timeout=30):
        return run([self.wpa_cli, "-i", self.ifname] + list(args), timeout=timeout)

    def _set_network_block(self, ssid, password, key_mgmt="wpa-psk", bssid=None):
        """把网络写进 wpa_supplicant 配置并 reconfigure。"""
        args = ["set_network", "id_str", ssid]
        args += ["ssid", '"%s"' % ssid]
        if bssid:
            args += ["bssid", '"%s"' % normalize_bssid(bssid)]
        if key_mgmt == "none":
            args += ["key_mgmt", "NONE"]
        else:
            args += ["psk", '"%s"' % (password or "")]
            if key_mgmt == "sae":
                args += ["key_mgmt", "SAE"]
            else:
                args += ["key_mgmt", "WPA-PSK"]
        r = self._wpa_cli(args)
        if not r.ok:
            raise AppError("NMCLI_FAILED", "wpa_cli set_network 失败", detail=r.to_dict())
        self._wpa_cli(["select_network", ssid])
        self._wpa_cli(["reconfigure"])
        return True

    def connect(self, req):
        req.validate()
        km = "sae" if req.auth_kind == AUTH_SAE else "wpa-psk"
        if req.auth_kind == AUTH_OPEN:
            km = "none"
        try:
            self._set_network_block(req.ssid, req.password, km, req.bssid)
        except AppError as exc:
            return ConnectResult(
                ok=False,
                phase=PHASE_REJECTED,
                message=exc.message,
                detail=exc.detail,
                ssid=req.ssid,
                bssid=req.bssid,
            )
        # 等关联
        deadline = time.time() + 30
        settle = int(((self.cfg.get("wifi", {}) or {}).get("connect", {}) or {}).get("settle_sec") or 8)
        time.sleep(settle)
        while time.time() < deadline:
            st = self.status()
            if st.connected:
                return ConnectResult(
                    ok=True,
                    phase=PHASE_ACTIVATED,
                    message="已连接 %s" % st.ssid,
                    ssid=st.ssid,
                    bssid=st.bssid,
                    ip=st.ip,
                    used_key_mgmt=km,
                )
            time.sleep(2)
        return ConnectResult(
            ok=False,
            phase=PHASE_HANDSHAKE_FAILED,
            message="配置已写入但未关联成功 —— 最可能是密码错误或加密方式不匹配",
            ssid=req.ssid,
            bssid=req.bssid,
            used_key_mgmt=km,
        )

    def disconnect(self):
        r = self._wpa_cli(["disconnect"])
        return ConnectResult(ok=r.ok, phase=PHASE_ACTIVATED if r.ok else PHASE_REJECTED)

    def activate_profile(self, profile_name, timeout=None):
        r = self._wpa_cli(["select_network", profile_name], timeout=timeout or 30)
        if not r.ok:
            return ConnectResult(
                ok=False, phase=PHASE_REJECTED, message="选择网络失败", detail=r.to_dict()
            )
        self._wpa_cli(["reconfigure"])
        time.sleep(int(((self.cfg.get("wifi", {}) or {}).get("connect", {}) or {}).get("settle_sec") or 8))
        st = self.status()
        return ConnectResult(
            ok=st.connected,
            phase=PHASE_ACTIVATED if st.connected else PHASE_HANDSHAKE_FAILED,
            message="已连接" if st.connected else "未关联",
            ssid=st.ssid,
            ip=st.ip,
        )

    # ---------- profile ----------
    def list_profiles(self):
        r = self._wpa_cli(["list_networks"], timeout=15)
        if not r.ok:
            return []
        out = []
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^(\d+)\s+(\S.*?)\s+(\[\S+\])", line)
            if m:
                out.append(ProfileInfo(name=m.group(2).strip(), iface=self.ifname, has_secret=True))
        return out

    def profile_exists(self, name):
        return any(p.name == name for p in self.list_profiles())

    def delete_profile(self, name):
        for p in self.list_profiles():
            if p.name == name:
                return self._wpa_cli(["remove_network", str(len(self.list_profiles()))]).ok
        return False

    def self_test(self):
        return [
            ("iw 可用", bool(self.iw), self.iw or "未找到"),
            ("wpa_cli 可用", bool(self.wpa_cli), self.wpa_cli or "未找到"),
        ]


def _split_bss(text):
    """把 ``iw scan dump`` 切成 ``[(bssid, block_text), ...]``。"""
    blocks = []
    cur = None
    for line in (text or "").splitlines():
        m = _BSS_RE.match(line)
        if m:
            if cur:
                blocks.append(cur)
            cur = [m.group(1), [line]]
        elif cur is not None:
            cur[1].append(line)
    if cur:
        blocks.append(cur)
    return [(b, "\n".join(lines)) for b, lines in blocks]
