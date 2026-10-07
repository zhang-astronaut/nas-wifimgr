"""错误类型与错误码表。

所有对外错误都带 ``code``（稳定字符串，供前端分支）与 ``retryable``
（前端据此决定是否自动重试），避免用 message 文案做判断。
"""

# 错误码 -> (默认提示, 是否可重试)
ERROR_CATALOG = {
    "BAD_REQUEST": ("请求格式错误", False),
    "VALIDATION_FAILED": ("参数校验未通过", False),
    "CSRF_FAILED": ("CSRF 校验失败，请刷新页面重试", False),
    "UNAUTHORIZED": ("未授权", False),
    "NOT_FOUND": ("对象不存在", False),
    "CONFLICT": ("状态冲突", False),
    "BUSY": ("设备忙，正在处理其他操作", True),
    "RATE_LIMITED": ("操作过于频繁", True),
    "NMCLI_TIMEOUT": ("nmcli 命令超时", True),
    "NMCLI_FAILED": ("nmcli 命令失败", False),
    "DBUS_TIMEOUT": ("NetworkManager 无响应（D-Bus 超时）", True),
    "NM_REJECTED": ("NetworkManager 拒绝了配置", False),
    "KEYFILE_REJECTED": ("生成的配置文件被 NM 拒绝", False),
    "AUTH_FAILED": ("认证失败，通常是密码错误", False),
    "HANDSHAKE_FAILED": ("配置已写入但握手失败", False),
    "AP_GONE": ("扫描时存在、连接时已消失的 AP", False),
    "WLAN0_BUSY": ("wlan0 正忙", True),
    "SAE_UNSUPPORTED": ("本机驱动/内核不支持 WPA3(SAE) 握手", False),
    "SCAN_PERMISSION_UNKNOWN": ("扫描权限状态未知", True),
    "DISK_READONLY": ("存储只读或空间不足", False),
    "DB_ERROR": ("数据库错误", True),
    "BACKEND_UNAVAILABLE": ("没有可用的后端", False),
    "INTERNAL": ("内部错误", False),
}


class AppError(Exception):
    """所有应用层错误的基类。``to_dict`` 直接作为 HTTP 错误体。"""

    def __init__(self, code, message=None, detail=None, hint=None, retryable=None):
        default_msg, default_retry = ERROR_CATALOG.get(code, ("未知错误", False))
        self.code = code
        self.message = message or default_msg
        self.detail = detail or {}
        self.hint = hint
        self.retryable = default_retry if retryable is None else bool(retryable)
        super().__init__("[%s] %s" % (self.code, self.message))

    def to_dict(self, request_id=None, ts=None):
        import time as _time

        return {
            "code": self.code,
            "message": self.message,
            "detail": self.detail,
            "retryable": self.retryable,
            "hint": self.hint,
            "request_id": request_id,
            "ts": _time.time() if ts is None else ts,
        }


class ValidationError(AppError):
    def __init__(self, message, detail=None, field=None):
        d = dict(detail or {})
        if field:
            d["field"] = field
        super().__init__("VALIDATION_FAILED", message, detail=d)


class BusyError(AppError):
    def __init__(self, message="设备忙，请稍后重试", detail=None, retry_after=None):
        d = dict(detail or {})
        if retry_after is not None:
            d["retry_after"] = retry_after
        super().__init__("BUSY", message, detail=d)


class RateLimitedError(AppError):
    def __init__(self, message="操作过于频繁，请稍后重试", retry_after=None):
        d = {}
        if retry_after is not None:
            d["retry_after"] = retry_after
        super().__init__("RATE_LIMITED", message, detail=d)


class BackendUnavailable(AppError):
    def __init__(self, message, detail=None):
        super().__init__("BACKEND_UNAVAILABLE", message, detail=detail)


class CsrfError(AppError):
    def __init__(self, message="CSRF 校验失败", detail=None):
        super().__init__("CSRF_FAILED", message, detail=detail)


class NotFoundError(AppError):
    def __init__(self, message="对象不存在", detail=None):
        super().__init__("NOT_FOUND", message, detail=detail)


class ConflictError(AppError):
    def __init__(self, message="状态冲突", detail=None):
        super().__init__("CONFLICT", message, detail=detail)


# 需要在日志/响应中脱敏的键名（小写比较）。
# nmcli 报错常回显参数，这是最容易被忽略的泄漏面。
SECRET_KEYS = frozenset(
    [
        "psk",
        "password",
        "passphrase",
        "sae_password",
        "wifi-sec.psk",
        "new_password",
        "old_password",
        "wifi_password",
    ]
)

_REDACTED = "***"


def redact(obj):
    """递归脱敏：命中 SECRET_KEYS 的值一律替换为 ``***``。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SECRET_KEYS:
                out[k] = _REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def redact_text(text, secrets=()):
    """从自由文本里抹掉已知密码字面量（nmcli 报错回显场景）。"""
    if not text:
        return text
    out = str(text)
    for s in secrets:
        if s and len(str(s)) >= 4 and str(s) in out:
            out = out.replace(str(s), _REDACTED)
    return out
