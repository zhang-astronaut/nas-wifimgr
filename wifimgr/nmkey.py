"""NM keyfile 渲染与应用（密码安全的核心）。

**为什么不用 argv。** ``nmcli con add ... wifi-sec.psk <pw>`` 会把 PSK 暴露在
``/proc/<pid>/cmdline``，同机任何用户（含 nginx 的 www-data）都能读到，``ps``
里也会瞬时可见。本模块全程不让密码进入命令行。

**三个实测坑（NM 1.22.10 + rtl8188fu，NAS 192.168.31.47）：**

D1. ``nmcli connection load FILE`` 会**假成功**：返回 rc=0 但 journalctl 里是
    ``settings: load: no settings plugin could load`` + ``audit: result="fail"``，
    profile 根本没创建。``/tmp`` 与 0700 私有目录都失败。
    → 唯一可行路线：**直接写入 keyfiles 目录** + ``nmcli connection reload``。
    → 因此所有判定都必须**回读校验**，绝不信 rc。

D2. keyfile 里 ``type`` 必须是 ``wifi``，不是 ``802-11-wireless``。
    写成后者症状与 D1 一模一样（plugin 不认），极易误判。

D3. ``bssid`` 在 keyfile 里是**分号分隔的十进制字节**，
    ``50:4F:3B:18:31:9B`` 要写成 ``80;79;59;24;49;155;``。
    写成转义冒号形式会导致连接必然 ``ssid-not-found``。
    而 ``ssid`` 反而**明文可用**（NM 存盘时才转分号十进制，读取时还原）。

另外 SAE 的密码字段在 NM keyfile 里就叫 ``psk``（``sae_password`` 是
wpa_supplicant.conf 的名字，两者不要混用）。
"""

import os
import re
import shutil
import time
import uuid as uuidlib

from .errors import AppError, ValidationError
from .terse import bssid_to_nm_bytes, normalize_bssid

KEYFILE_DIR = "/etc/NetworkManager/system-connections"

# 只接受这些可选 key，其余一律拒绝 —— 防止把任意内容注入 keyfile。
# 注意：pmf 在 NM 1.22 上很可能不被识别（字段名 802-11-wireless-security.mfp
# 是后来才有的），所以它走分级降级，默认不写。
OPTIONAL_KEYS = ("pmf", "ieee80211ax", "powersave")

VALID_KEY_MGMT = ("none", "wpa-psk", "sae", "wep")

# GLib keyfile 值转义：首字符为分隔符/注释符时必须转义。
_ESCAPES = {
    "\\": "\\\\",
    ";": "\\;",
    ":": "\\:",
    "#": "\\#",
    "[": "\\[",
    "]": "\\]",
    "=": "\\=",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\s",
    " ": "\\s",
}


def esc(value):
    """转义单个 keyfile 值。UTF-8 原样保留（GLib keyfile 天然 UTF-8 安全）。

    注意：GLib 用 ``\\s`` 表示「空白」，空格、制表、换行都会落到同一个字符上，
    所以**制表符和空格不可区分地映射为 ``\\s``**。因此 :func:`unesc` 无法
    还原原始制表符 —— 往返测试只对不含制表符的输入成立。
    """
    if value is None:
        return ""
    out = []
    for ch in str(value):
        out.append(_ESCAPES.get(ch, ch))
    return "".join(out)


def unesc(value):
    """反转义，用于测试往返一致性与排查 keyfile 内容。"""
    if not value:
        return ""
    out = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n:
            nxt = value[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "s":
                out.append(" ")
            elif nxt == "t":
                out.append("\t")
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def stable_uuid(profile_name):
    """由 profile 名派生稳定 uuid —— 幂等的关键。

    同一 profile 名永远算出同一 uuid，所以重复写入是「覆盖」而非「新建」，
    不会在 NM 里堆积垃圾 profile。
    """
    return str(uuidlib.uuid5(uuidlib.NAMESPACE_DNS, "wifimgr:" + profile_name))


def validate_psk(password):
    """校验 WPA 密码。返回 ``"hex"`` 或 ``"passphrase"``。"""
    if password is None:
        raise ValidationError("缺少密码", field="password")
    text = str(password)
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        return "hex"
    n = len(text.encode("utf-8"))
    if n < 8 or n > 63:
        raise ValidationError("WPA 密码需 8–63 字节（当前 %d 字节）" % n, field="password")
    return "passphrase"


def render_keyfile(
    profile_name,
    ssid,
    password=None,
    key_mgmt="wpa-psk",
    uuid=None,
    bssid=None,
    iface="wlan0",
    autoconnect=True,
    autoconnect_retries=0,
    priority=100,
    hidden=False,
    extra=None,
):
    """渲染 ``.nmconnection`` 内容。**纯函数、无 IO、可离线单测。**

    ``extra`` 只接受 :data:`OPTIONAL_KEYS` 白名单内的 key。
    """
    if not profile_name:
        raise ValidationError("profile_name 不能为空", field="profile_name")
    if not ssid:
        raise ValidationError("SSID 不能为空（隐藏网络也必须提供 SSID）", field="ssid")
    if "\n" in ssid or "\r" in ssid:
        raise ValidationError("SSID 不允许换行", field="ssid")
    if len(ssid.encode("utf-8")) > 32:
        raise ValidationError("SSID 超长（上限 32 字节）", field="ssid")
    if key_mgmt not in VALID_KEY_MGMT:
        raise ValidationError("非法 key-mgmt: %r" % (key_mgmt,), field="key_mgmt")

    if key_mgmt != "none":
        validate_psk(password)

    extra = dict(extra or {})
    for k in extra:
        if k not in OPTIONAL_KEYS:
            raise ValidationError("不允许的可选 key: %r" % (k,), field="extra")

    lines = []
    lines.append("[connection]")
    lines.append("id=%s" % esc(profile_name))
    lines.append("uuid=%s" % (uuid or stable_uuid(profile_name)))
    # D2: 必须是 wifi，不是 802-11-wireless
    lines.append("type=wifi")
    lines.append("interface-name=%s" % esc(iface))
    lines.append("autoconnect=%s" % ("true" if autoconnect else "false"))
    if key_mgmt != "none":
        # 0 = forever。实测 NM 1.22 的 nmcli 会显示 "(forever)"
        lines.append("autoconnect-retries=%d" % int(autoconnect_retries))
    lines.append("autoconnect-priority=%d" % int(priority))
    lines.append("permissions=")
    lines.append("")

    lines.append("[wifi]")
    lines.append("mode=infrastructure")
    # ssid 明文可用（NM 存盘时才转分号十进制）
    lines.append("ssid=%s" % esc(ssid))
    if bssid:
        # D3: 分号十进制字节
        lines.append("bssid=%s" % bssid_to_nm_bytes(normalize_bssid(bssid)))
    if hidden:
        lines.append("hidden=yes")
    lines.append("")

    lines.append("[wifi-security]")
    lines.append("auth-alg=open")
    lines.append("key-mgmt=%s" % key_mgmt)
    if key_mgmt == "wep":
        lines.append("wep-key0=%s" % esc(password))
        lines.append("wep-key-type=pass")
    elif key_mgmt != "none":
        lines.append("psk=%s" % esc(password))
    for k in OPTIONAL_KEYS:
        if k in extra:
            lines.append("%s=%s" % (k, esc(extra[k])))
    lines.append("")

    lines.append("[ipv4]")
    lines.append("method=auto")
    lines.append("")
    lines.append("[ipv6]")
    lines.append("method=auto")
    lines.append("")
    return "\n".join(lines)


_PROFILE_NAME_OK = re.compile(r"^[A-Za-z0-9一-鿿][A-Za-z0-9一-鿿._\- ]*$")


def keyfile_path(keyfiles_dir, profile_name):
    """profile 名 -> keyfile 路径。

    NM 直接用 profile 名做文件名，所以必须**拒绝**（而非静默过滤）任何含
    路径分隔符、``..``、控制字符的名字 —— 静默过滤会造成「写到了另一个名字」
    的隐蔽错误，比报错更难查。
    允许字母、数字、下划线、连字符、点、空格，以及中文（SSID 可能是中文）。
    """
    name = profile_name or ""
    if not name:
        raise ValidationError("profile_name 不能为空", field="profile_name")
    if len(name.encode("utf-8")) > 64:
        raise ValidationError("profile_name 过长（上限 64 字节）", field="profile_name")
    if not _PROFILE_NAME_OK.match(name):
        raise ValidationError(
            "profile_name 含非法字符（仅允许中文、字母数字、'.'、'-'、'_'、空格）: %r"
            % (profile_name,),
            field="profile_name",
        )
    if name.strip() != name:
        raise ValidationError("profile_name 首尾不能有空格", field="profile_name")
    return os.path.join(keyfiles_dir, name + ".nmconnection")


def shred_file(path, passes=3):
    """覆写后删除。

    注意：``/etc/NetworkManager/system-connections`` 在多数 rootfs 上**不是**
    tmpfs，所以覆写不能保证不可恢复 —— 真正的防线是「文件只以 0600 root 存在，
    且由 NM 自己管理」。这里做覆写只是尽最大努力。
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    try:
        with open(path, "r+b", buffering=0) as fh:
            for _ in range(max(1, passes)):
                fh.seek(0)
                fh.write(b"\0" * size)
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def snapshot_existing(keyfiles_dir, profile_name, snapshot_dir, keep=20):
    """覆盖前把现有 keyfile 备份到快照目录。

    我们会改写用户已有的 profile（比如遗留的 RD08_IoT），必须留还原路径。
    """
    src = keyfile_path(keyfiles_dir, profile_name)
    if not os.path.isfile(src):
        return None
    if not snapshot_dir:
        return None
    try:
        os.makedirs(snapshot_dir, mode=0o700, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dst = os.path.join(snapshot_dir, "%s-%s.nmconnection" % (stamp, profile_name))
        n = 1
        while os.path.exists(dst):
            dst = os.path.join(
                snapshot_dir, "%s-%s-%d.nmconnection" % (stamp, profile_name, n)
            )
            n += 1
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
        _prune_snapshots(snapshot_dir, keep)
        return dst
    except OSError:
        return None


def _prune_snapshots(snapshot_dir, keep):
    try:
        entries = [
            os.path.join(snapshot_dir, f)
            for f in os.listdir(snapshot_dir)
            if f.endswith(".nmconnection")
        ]
    except OSError:
        return
    entries.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    for old in entries[max(0, int(keep)) :]:
        try:
            os.unlink(old)
        except OSError:
            pass


def cleanup_stale_tmp(base_dir, ttl_sec=3600):
    """清扫崩溃残留的临时目录。"""
    removed = []
    try:
        names = os.listdir(base_dir)
    except OSError:
        return removed
    now = time.time()
    for name in names:
        path = os.path.join(base_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if now - st.st_mtime > ttl_sec:
            shutil.rmtree(path, ignore_errors=True)
            removed.append(path)
    return removed


class KeyfileRejected(AppError):
    def __init__(self, message, detail=None):
        super().__init__("KEYFILE_REJECTED", message, detail=detail)


def write_keyfile(path, content):
    """以 0600 原子写入 keyfile。"""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
    tmp = os.path.join(directory, ".%s.wifimgr-tmp" % os.path.basename(path))
    body = content if content.endswith("\n") else content + "\n"
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
    os.chmod(tmp, 0o600)
    try:
        os.chown(tmp, 0, 0)
    except (OSError, AttributeError):
        pass  # 非 root 或不支持 chown，权限位已足够
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    st = os.stat(path)
    mode = st.st_mode & 0o777
    # POSIX 上必须是 0600。Windows 的 os.chmod 只映射只读位、且会把组/其他
    # 位置成 0666，所以仅在 POSIX 平台上断言 —— 开发机是 Windows。
    if os.name == "posix" and mode != 0o600:
        raise KeyfileRejected(
            "keyfile 权限异常：期望 0600，实际 %o" % mode, detail={"path": path}
        )
    return path
