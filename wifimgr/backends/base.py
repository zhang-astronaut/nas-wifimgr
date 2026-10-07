"""后端抽象基类与共用工具。"""

import re

from ..models import (
    AUTH_MIXED,
    AUTH_OPEN,
    AUTH_PSK,
    AUTH_SAE,
    AUTH_UNKNOWN,
    AUTH_WEP,
    Capabilities,
    ConnStatus,
    ConnectResult,
    ProfileInfo,
    ScanEntry,
    SEC_OPEN,
    SEC_UNKNOWN,
    SEC_WEP,
    SEC_WPA1,
    SEC_WPA2,
    SEC_WPA2_WPA3,
    SEC_WPA3,
)

# NM 状态字符串 -> 是否认为"已连接"。用于 settle 判定与守护循环。
STATE_CONNECTED = "connected"
NM_ACTIVE_STATES = frozenset(["connected"])
NM_BUSY_STATES = frozenset(
    [
        "activating",
        "deactivating",
        "reactivating",
        "connecting (configuring)",
        "connecting (need-auth)",
        "connecting (getting ip configuration)",
    ]
)


def security_from_flags(security_field, wpa_flags="", rsn_flags=""):
    """由 ``SECURITY`` 文本 + WPA/RSN flags 归一化出 ``(security, auth_kind)``。

    ``SECURITY`` 字段只能说明「WPA2 WPA3 = 混合」，无法证明真的支持 SAE；
    而 ``RSN-FLAGS`` 里出现 ``sae`` 才是 SAE 的可靠证据。
    所以两个都要看，flags 优先。
    """
    sec = (security_field or "").upper()
    tokens = set((wpa_flags or "").split()) | set((rsn_flags or "").split())
    has_sae = "sae" in tokens
    has_psk = "psk" in tokens
    # WPA1 的判据：WPA-FLAGS 非空且含 tkip/pkcc（RSN 里不会有这些）
    wpa1 = bool({"tkip", "pkcc_tkip", "tkip+tkip"} & set((wpa_flags or "").split()))

    if has_sae and has_psk:
        auth = AUTH_MIXED
    elif has_sae:
        auth = AUTH_SAE
    elif has_psk:
        auth = AUTH_PSK
    elif has_psk or has_sae:
        auth = AUTH_PSK
    elif not tokens and not sec:
        auth = AUTH_OPEN
    elif "WEP" in sec:
        auth = AUTH_WEP
    else:
        auth = AUTH_UNKNOWN

    if auth in (AUTH_OPEN, AUTH_UNKNOWN) and "WEP" in sec:
        auth = AUTH_WEP

    # security 展示串
    if "WPA3" in sec and "WPA2" in sec:
        norm = SEC_WPA2_WPA3
    elif "WPA3" in sec:
        norm = SEC_WPA3
    elif "WPA2" in sec:
        norm = SEC_WPA2
    elif "WPA1" in sec:
        norm = SEC_WPA1
    elif "WEP" in sec:
        norm = SEC_WEP
    elif not sec and not tokens:
        norm = SEC_OPEN
    else:
        norm = SEC_UNKNOWN
    return norm, auth


def signal_to_int(raw):
    """``SIGNAL`` -> int dBm 近似值（nmcli 的百分比）。

    nmcli 的 SIGNAL 是 0..100 的质量分，UI 展示用 dBm 更直观。
    这里只做粗略线性映射，**仅用于排序与展示**，不要当真值。
    """
    try:
        pct = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if pct <= 0:
        return -100
    if pct >= 100:
        return -30
    # 100% -> -30 dBm, 0% -> -100 dBm（线性近似）
    return int(round(-100 + (pct / 100.0) * 70))


_SIGNAL_RE = re.compile(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", re.I)
_SSID_RE = re.compile(r"^\s*SSID:\s*(.*)$", re.M)


def parse_iw_link(text):
    """解析 ``iw dev wlan0 link`` 输出。

    实测输出形如::

        Connected to 62:4f:3b:18:31:9b (on wlan0)
                SSID: 密码是八个八wifi5
                freq: 2412
                signal: -16 dBm

    注意 ``iw`` 把非 ASCII SSID 输出成 ``\\xe5\\xaf\\x86`` 形式的 C 转义，
    需要解码回真实 UTF-8 字节。
    """
    out = {"ssid": "", "bssid": "", "freq": None, "signal": None, "connected": False}
    if not text:
        return out
    if "Not connected" in text:
        return out
    m = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", text)
    if m:
        out["connected"] = True
        out["bssid"] = m.group(1).upper()
    m = _SSID_RE.search(text)
    if m:
        out["ssid"] = decode_iw_ssid(m.group(1).strip())
    m = re.search(r"freq:\s*(\d+)", text)
    if m:
        out["freq"] = int(m.group(1))
    m = _SIGNAL_RE.search(text)
    if m:
        out["signal"] = int(round(float(m.group(1))))
    return out


_SSID_RE = re.compile(r"^\s*SSID:\s*(.*)$", re.M)


def decode_iw_ssid(raw):
    """``\\xe5\\xaf\\x86...`` -> 真实 UTF-8 字符串。非转义时原样返回。

    ``iw`` 对非 ASCII SSID 输出 C 风格转义，实测样本::

        SSID: \\xe5\\xaf\\x86\\xe7\\xa0\\x81...

    解码要点：逐段识别 ``\\xNN`` 并累积**字节**，最后一次性 UTF-8 解码。
    不能逐字符 append 字符串，那样会破坏多字节序列。
    """
    if not raw:
        return ""
    # 早退判断必须同时认大小写 'x'，否则 "\\X41" 会被原样返回。
    if "\\x" not in raw and "\\X" not in raw:
        return raw
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        # 匹配 \xNN（大小写 x 都要认）
        if ch == "\\" and raw[i + 1 : i + 2].lower() == "x" and i + 4 <= n:
            hexpart = raw[i + 2 : i + 4]
            if len(hexpart) == 2:
                try:
                    out.append(int(hexpart, 16))
                    i += 4
                    continue
                except ValueError:
                    pass
        # 非转义字符：把它的 UTF-8 字节追加进去
        out.extend(ch.encode("utf-8", "surrogatepass"))
        i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("utf-8", "replace")


class Backend(object):
    """后端接口。子类必须实现带 ``probe`` 的类方法与各实例方法。"""

    NAME = "base"

    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.ifname = (cfg.get("wifi", {}) or {}).get("ifname", "wlan0")

    # ---- 能力 ----------------------------------------------------------
    @classmethod
    def probe(cls, cfg):
        """返回 Capabilities 或 None。**必须无副作用、不改系统状态。**"""
        raise NotImplementedError

    def capabilities(self):
        caps = self.probe(self.cfg)
        if caps is None:
            from ..errors import BackendUnavailable

            raise BackendUnavailable("后端 %s 不可用" % self.NAME)
        return caps

    # ---- 扫描 ----------------------------------------------------------
    def scan(self, force=True):
        raise NotImplementedError

    # ---- 状态 ----------------------------------------------------------
    def status(self):
        raise NotImplementedError

    # ---- 连接 ----------------------------------------------------------
    def connect(self, req):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError

    def activate_profile(self, profile_name):
        raise NotImplementedError

    # ---- profile -------------------------------------------------------
    def list_profiles(self):
        raise NotImplementedError

    def profile_exists(self, name):
        raise NotImplementedError

    def delete_profile(self, name):
        raise NotImplementedError

    # ---- 健康 ----------------------------------------------------------
    def self_test(self):
        return [("backend", True, self.NAME)]


__all__ = [
    "Backend",
    "Capabilities",
    "ConnStatus",
    "ConnectResult",
    "ProfileInfo",
    "ScanEntry",
    "NM_ACTIVE_STATES",
    "NM_BUSY_STATES",
    "security_from_flags",
    "signal_to_int",
    "parse_iw_link",
    "decode_iw_ssid",
]
