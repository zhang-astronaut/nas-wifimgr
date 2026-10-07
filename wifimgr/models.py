"""数据模型：扫描条目、连接状态、连接请求/结果、能力探测。

刻意用 ``__slots__`` 的普通类而非 dataclass —— 目标机 Python 3.8 上
dataclasses 可用，但这些对象要在解析热路径上大量构造，轻量一点更好。
"""

from .errors import ValidationError

# security 归一化取值
SEC_OPEN = "open"
SEC_WEP = "wep"
SEC_WPA1 = "wpa1"
SEC_WPA2 = "wpa2"
SEC_WPA3 = "wpa3"
SEC_WPA2_WPA3 = "wpa2-wpa3"
SEC_UNKNOWN = "unknown"

# auth_kind 归一化取值（决定用哪种 key-mgmt 去连）
AUTH_OPEN = "open"
AUTH_PSK = "psk"
AUTH_SAE = "sae"
AUTH_MIXED = "mixed"  # AP 同时声明 psk 与 sae
AUTH_WEP = "wep"
AUTH_UNKNOWN = "unknown"

# 连接结果四档
PHASE_ACTIVATED = "activated"
PHASE_HANDSHAKE_FAILED = "accepted_but_handshake_failed"
PHASE_REJECTED = "rejected"
PHASE_TIMEOUT = "timeout"
PHASE_BUSY = "busy"
PHASE_SKIPPED = "skipped"


class Capabilities(object):
    """后端能力。``sae`` 只代表**配置层**支持，不代表握手一定成功。

    实测（NM 1.22.10 + wpa_supplicant 2.9 + rtl8188fu 出厂驱动）：
    配置层可以写入 ``key-mgmt=sae`` 并正确回读，但真实握手必然
    ``ssid-not-found`` 超时。所以 UI 不能仅凭 ``sae=True`` 就承诺 WPA3 可用。
    """

    __slots__ = (
        "name",
        "can_scan",
        "can_connect",
        "sae_configurable",
        "sae_handshake_verified",
        "sae_evidence",
        "pmf",
        "hidden_scan",
        "notes",
    )

    def __init__(
        self,
        name,
        can_scan=True,
        can_connect=True,
        sae_configurable=False,
        sae_handshake_verified=False,
        sae_evidence=None,
        pmf="unknown",
        hidden_scan=False,
        notes=None,
    ):
        self.name = name
        self.can_scan = bool(can_scan)
        self.can_connect = bool(can_connect)
        self.sae_configurable = bool(sae_configurable)
        self.sae_handshake_verified = bool(sae_handshake_verified)
        self.sae_evidence = list(sae_evidence or [])
        self.pmf = pmf
        self.hidden_scan = bool(hidden_scan)
        self.notes = list(notes or [])

    def to_dict(self):
        # 给前端一个可直接决策的布尔：只有配置层+握手都验证过才建议用 SAE
        sae_usable = self.sae_configurable and self.sae_handshake_verified
        return {
            "name": self.name,
            "can_scan": self.can_scan,
            "can_connect": self.can_connect,
            "sae_configurable": self.sae_configurable,
            "sae_handshake_verified": self.sae_handshake_verified,
            "sae_usable": sae_usable,
            "sae_evidence": self.sae_evidence,
            "pmf": self.pmf,
            "hidden_scan": self.hidden_scan,
            "notes": self.notes,
        }


class ScanEntry(object):
    """一个扫描到的 AP/BSSID。

    注意：同一 SSID 可能有多个 BSSID（AP 多频/多天线），这里 **逐 BSSID**
    保留，不在解析层合并 —— 合并会丢掉信号最强的那个，反而影响连接选择。
    展示层的分组由前端做。
    """

    __slots__ = (
        "ssid",
        "bssid",
        "signal",
        "freq",
        "security",
        "auth_kind",
        "wpa_flags",
        "rsn_flags",
        "in_use",
        "iface",
        "hidden",
        "saved",
        "profile_name",
    )

    def __init__(
        self,
        ssid="",
        bssid="",
        signal=None,
        freq="",
        security="",
        auth_kind=AUTH_UNKNOWN,
        wpa_flags="",
        rsn_flags="",
        in_use=False,
        iface="",
        profile_name=None,
    ):
        self.ssid = ssid or ""
        self.bssid = bssid or ""
        self.signal = signal
        self.freq = freq or ""
        self.security = security or ""
        self.auth_kind = auth_kind or AUTH_UNKNOWN
        self.wpa_flags = wpa_flags or ""
        self.rsn_flags = rsn_flags or ""
        self.in_use = bool(in_use)
        self.iface = iface or ""
        self.profile_name = profile_name
        self.hidden = not bool(self.ssid)
        self.saved = False

    @property
    def key(self):
        """同一「SSID+BSSID」的唯一键。"""
        return "%s\x00%s" % (self.ssid, self.bssid)

    def to_dict(self, hidden_label="(隐藏网络)"):
        display = self.ssid if self.ssid else hidden_label
        if self.hidden and self.bssid:
            display = "%s %s" % (hidden_label, self.bssid[-6:])
        return {
            "ssid": self.ssid,
            "display": display,
            "bssid": self.bssid,
            "signal": self.signal,
            "freq": self.freq,
            "security": self.security or "unknown",
            "auth_kind": self.auth_kind,
            "wpa_flags": self.wpa_flags,
            "rsn_flags": self.rsn_flags,
            "in_use": self.in_use,
            "hidden": self.hidden,
            "saved": self.saved,
            "profile_name": self.profile_name,
            "iface": self.iface,
        }


class ConnStatus(object):
    """当前连接状态。``source`` 说明数据来自哪一级，便于排障。"""

    __slots__ = (
        "connected",
        "source",
        "confidence",
        "ssid",
        "bssid",
        "profile_name",
        "iface",
        "ip",
        "signal",
        "state",
        "checked_at",
        "detail",
    )

    def __init__(
        self,
        connected=False,
        source="none",
        confidence=0.0,
        ssid="",
        bssid="",
        profile_name="",
        iface="",
        ip="",
        signal=None,
        state="",
        checked_at=None,
        detail=None,
    ):
        self.connected = bool(connected)
        self.source = source
        self.confidence = float(confidence)
        self.ssid = ssid or ""
        self.bssid = bssid or ""
        self.profile_name = profile_name or ""
        self.iface = iface or ""
        self.ip = ip or ""
        self.signal = signal
        self.state = state or ""
        self.checked_at = checked_at
        self.detail = dict(detail or {})

    def to_dict(self):
        return {
            "connected": self.connected,
            "source": self.source,
            "confidence": self.confidence,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "profile_name": self.profile_name,
            "iface": self.iface,
            "ip": self.ip,
            "signal": self.signal,
            "state": self.state,
            "checked_at": self.checked_at,
            "detail": self.detail,
        }


class ConnectRequest(object):
    __slots__ = (
        "ssid",
        "bssid",
        "password",
        "auth_kind",
        "profile_name",
        "remember",
        "sae_policy",
        "bssid_lock",
        "iface",
        "timeout",
        "idempotency_key",
    )

    def __init__(
        self,
        ssid="",
        bssid="",
        password=None,
        auth_kind=AUTH_UNKNOWN,
        profile_name=None,
        remember=True,
        sae_policy="psk_first",
        bssid_lock=False,
        iface="wlan0",
        timeout=None,
        idempotency_key=None,
    ):
        self.ssid = ssid or ""
        self.bssid = bssid or ""
        self.password = password
        self.auth_kind = auth_kind or AUTH_UNKNOWN
        self.profile_name = profile_name
        self.remember = bool(remember)
        self.sae_policy = sae_policy or "psk_first"
        self.bssid_lock = bool(bssid_lock)
        self.iface = iface or "wlan0"
        self.timeout = timeout
        self.idempotency_key = idempotency_key

    def validate(self, existing_profiles=None):
        """提交前校验。``existing_profiles`` 用于拒绝覆盖非本应用管理的 profile。"""
        if not self.ssid:
            raise ValidationError("SSID 不能为空", field="ssid")
        if len(self.ssid.encode("utf-8")) > 32:
            raise ValidationError("SSID 超长（上限 32 字节）", field="ssid")
        if "\n" in self.ssid or "\r" in self.ssid:
            raise ValidationError("SSID 不允许换行", field="ssid")
        if self.auth_kind in (AUTH_PSK, AUTH_SAE, AUTH_MIXED):
            if self.password is None or self.password == "":
                raise ValidationError("该网络需要密码", field="password")
        if self.sae_policy not in ("psk_first", "force_psk", "force_sae"):
            raise ValidationError(
                "sae_policy 只能是 psk_first/force_psk/force_sae", field="sae_policy"
            )
        return True

    def to_public_dict(self):
        """给日志用：**不含密码**。"""
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "auth_kind": self.auth_kind,
            "profile_name": self.profile_name,
            "remember": self.remember,
            "sae_policy": self.sae_policy,
            "bssid_lock": self.bssid_lock,
            "iface": self.iface,
        }


class ConnectResult(object):
    __slots__ = (
        "ok",
        "phase",
        "message",
        "detail",
        "ssid",
        "bssid",
        "profile_name",
        "requested_key_mgmt",
        "used_key_mgmt",
        "duration_ms",
        "attempts",
        "ip",
    )

    def __init__(
        self,
        ok=False,
        phase=PHASE_REJECTED,
        message="",
        detail=None,
        ssid="",
        bssid="",
        profile_name="",
        requested_key_mgmt=None,
        used_key_mgmt=None,
        duration_ms=0,
        attempts=None,
        ip="",
    ):
        self.ok = bool(ok)
        self.phase = phase
        self.message = message
        self.detail = dict(detail or {})
        self.ssid = ssid or ""
        self.bssid = bssid or ""
        self.profile_name = profile_name or ""
        self.requested_key_mgmt = requested_key_mgmt
        self.used_key_mgmt = used_key_mgmt
        self.duration_ms = int(duration_ms or 0)
        self.attempts = list(attempts or [])
        self.ip = ip or ""

    def to_dict(self):
        return {
            "ok": self.ok,
            "phase": self.phase,
            "message": self.message,
            "detail": self.detail,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "profile_name": self.profile_name,
            "requested_key_mgmt": self.requested_key_mgmt,
            "used_key_mgmt": self.used_key_mgmt,
            "duration_ms": self.duration_ms,
            "attempts": self.attempts,
            "ip": self.ip,
        }


class ProfileInfo(object):
    """NM profile 的只读视图。**只有 has_secret 布尔，绝不携带密码。**"""

    __slots__ = ("name", "uuid", "type", "iface", "autoconnect", "key_mgmt", "has_secret", "managed")

    def __init__(
        self,
        name="",
        uuid="",
        type="",
        iface="",
        autoconnect=False,
        key_mgmt="",
        has_secret=False,
        managed=False,
    ):
        self.name = name
        self.uuid = uuid
        self.type = type
        self.iface = iface
        self.autoconnect = bool(autoconnect)
        self.key_mgmt = key_mgmt
        self.has_secret = bool(has_secret)
        self.managed = bool(managed)

    def to_dict(self):
        return {
            "profile_name": self.name,
            "uuid": self.uuid,
            "type": self.type,
            "iface": self.iface,
            "autoconnect": self.autoconnect,
            "key_mgmt": self.key_mgmt,
            "has_secret": self.has_secret,
            "managed": self.managed,
        }
